---
name: evidence-hygiene
description: Evidence capture, redaction, and packaging standards for bug bounty reports. Covers Burp Suite export settings, screenshot requirements, video evidence, request/response formatting, redaction rules (tokens, PII, production credentials), evidence folder structure, and triager-friendly report packaging. Use when assembling proof-of-concept materials before submitting a bug bounty report. Chinese trigger: 证据整理、evidence packaging、redaction、Burp导出、截图标准、证据收集
---

# Evidence Hygiene

Capture, redact, and package proof-of-concept evidence for bug bounty reports.

---

## EVIDENCE PHILOSOPHY

```
EVIDENCE LIFECYCLE:
1. CAPTURE — Record the raw request/response before modifying
2. REDACT — Remove tokens, credentials, production secrets
3. ORGANIZE — Structure into clear, labeled evidence blocks
4. VERIFY — Confirm the evidence proves the claim
5. PACKAGE — Format for triager consumption (copy-paste friendly)
```

### Evidence hierarchy (strongest to weakest)

| Level | Description | Use case |
|---|---|---|
| 1 — Video | Screen recording showing full attack flow | Complex chains, race conditions |
| 2 — Live browser + DevTools | Network panel with headers/body expanded | DOM-based findings, runtime vulns |
| 3 — Burp Repeater req + res | Copy-paste ready, raw HTTP | Standard findings |
| 4 — Screenshot with proof | Request shown AND response shown | Quick submission support |
| 5 — Response-only screenshot | Shows impact but not attack | Not sufficient alone |
| 6 — Text description | Request+response in plain text | Minimum viable |

**Minimum requirement:** Level 3+ (raw request + response in text) for every submission.

---

## BURP SUITE EXPORT STANDARDS

### Request/Response Export

```
Burp → Repeater → Send request → Right-click response → Copy to file

Export format options:
1. HTTP request/response (Burp native) — best for re-import
2. Plain text — best for copy-paste into reports
3. Base64 — for binary bodies (images, PDFs)

Recommended: Export BOTH request AND response together as a text block
```

**Format template for report inclusion:**
```http
POST /api/users/456 HTTP/1.1
Host: target.com
Authorization: Bearer [REDACTED]
Content-Type: application/json
Accept: application/json

{"userId": 456, "email": "victim@example.com"}

HTTP/1.1 200 OK
Content-Type: application/json

{"id": 456, "email": "victim@example.com", "name": "Victim User", "phone": "555-0123"}
```

### Burp Suite Project Export (for program review requests)

```
If the triager asks for a Burp project file:
1. Burp → Project options → Save project
2. Export ONLY the relevant tab(s) (target, proxy history for this finding)
3. Use "Export selected items" not full project export
4. Redact tokens in the exported items BEFORE sharing

Do NOT export:
- Full proxy history (contains all your reconnaissance)
- Other programs' findings
- Real credentials from other assessments
```

### Logger++ Extension for Evidence Collection

```
Logger++ (Burp extension) auto-logs all requests/responses.
Setup:
1. BApp Store → Install Logger++
2. Configure log format (include headers, bodies)
3. Filter by domain to isolate evidence per-program

Advantages:
- Automatic capture; no manual copy-paste
- Timestamps logged
- Can export tab-separated log for reports
- Scales well for multi-finding reports
```

---

## SCREENSHOT STANDARDS

### Minimum screenshot requirements

Every submitted finding MUST include at least one screenshot showing:
- Attack request visible in Burp/browser
- Response showing impact (actual data, 200 status, or error)
- URL bar showing target domain
- Timestamp visible (or system clock in corner)

**Screenshot layout:**
```
[Browser window]
┌────────────────────────────────────────────┐
│ URL: https://target.com/api/users/456       │
├────────────────────────────────────────────┤
│ Request (in Repeater or DevTools):         │
│   GET /api/users/456 HTTP/1.1              │
│   Authorization: Bearer [REDACTED]         │
│                                            │
│ Response:                                  │
│   HTTP/1.1 200 OK                          │
│   { "email": "victim@example.com", ... }   │
│                                            │
│ [Date: 2025-01-15 10:30:45 UTC]            │
└────────────────────────────────────────────┘
```

### Screenshot checklist

- [ ] URL bar visible with in-scope domain
- [ ] Full request headers visible (method, path, auth)
- [ ] Full response body visible (showing actual data)
- [ ] Response status code visible
- [ ] Timestamp or date visible
- [ ] No production credentials visible
- [ ] No other user's full PII visible (consider partial redaction)

### Redaction in screenshots

**Always redact:**
- Full authorization tokens (show first/last 4 chars only)
- Session cookies
- API keys and secrets
- Passwords in request bodies
- Full credit card numbers
- Government ID numbers
- Production database credentials

**Redaction technique:**
- Screenshot tool: Use rectangle tool with solid black fill
- In reports: Replace with `[REDACTED]` or `[TOKEN-REDACTED]`
- In Burp: Right-click → "Redact" before export

### Screenshot tool recommendations

| Tool | Platform | Best for |
|---|---|---|
| Greenshot | Windows | Quick annotation, region capture |
| Snipping Tool | Windows | Native, basic |
| Lightshot | Windows/Mac | Annotation, URL sharing (not for reports) |
| Preview | macOS | Annotation, crop |
| Flameshot | Linux/Windows | Advanced annotation |
| ShareX | Windows | Automated capture, GIF |

**Settings to check:**
- Save as PNG (lossless, best for text readability)
- Enable timestamps in filename: `target-idor-20250115-103045.png`
- If sharing with triager: ensure file size < 10MB

---

## VIDEO EVIDENCE

### When video is required

- Race conditions (hard to show with screenshots)
- Multi-step attack chains
- Time-based blind injection
- CSRF requiring victim simulation
- Any finding where screenshots alone don't show the attack flow

### Video recording standards

```
Tool options:
- OBS Studio (free, high quality)
- Windows Game Bar (Win+G, built-in)
- QuickTime Screen Record (macOS)
- Burp Suite (via Logger++ extension)
- asciinema (terminal only)

Settings:
- Resolution: 1920x1080 minimum
- Frame rate: 30fps
- Audio: narrate what you're showing
- Length: under 3 minutes preferred; under 5 minutes maximum
```

**Video structure (template):**
```
[0:00-0:15] Overview:
  "This is a PoC for [vuln class] on [endpoint].
   I'm logged in as [attacker account description].
   I'll demonstrate [impact]."

[0:15-1:00] Setup:
  Show current account
  Navigate to relevant page
  Show baseline behavior

[1:00-2:00] Attack execution:
  Show the request being sent
  Show response received
  Show intermediate steps

[2:00-2:30] Impact demonstration:
  Show the result proving impact
  Highlight the sensitive data or state change

[2:30-3:00] Cleanup note:
  "I have not modified production data"
  "I've reverted the change"
```

### Video editing checklist

- [ ] Trim to under 3 minutes
- [ ] Remove personal information from browser tabs
- [ ] Ensure URL bar is visible throughout
- [ ] Add narration or text overlays for key moments
- [ ] Export as MP4 (H.264) for compatibility

---

## REQUEST/RESPONSE FORMATTING

### HTTP request block formatting

```http
POST /api/users/123 HTTP/1.1
Host: target.com
Authorization: Bearer eyJhbG... [REDACTED]
Content-Type: application/json
Accept: application/json
X-CSRF-Token: abc123... [REDACTED]

{"userId": 123, "role": "admin", "email": "attacker@evil.com"}
```

**Rules:**
- Show full first line: method, path, HTTP version
- Show all headers
- Truncate values > 20 chars with `[REDACTED]` or first/last 4 chars
- Show full request body (this is where the vulnerability lives)
- Include CSRF tokens, content-type, accept headers

### Response block formatting

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=[REDACTED]

{"id": 123, "role": "admin", "email": "attacker@evil.com", "name": "Victim User"}
```

**Rules:**
- Show status line
- Show relevant headers (content-type, set-cookie)
- Show full response body (proves the impact)
- Highlight or annotate the sensitive data

### WebSocket message evidence

```json
// Sent:
{"action": "subscribe", "channel": "user_456"}

// Received:
{"type": "private_data", "user": "victim", "email": "victim@example.com", "ssn": "123-45-6789"}
```

### GraphQL evidence

```graphql
# Request:
query {
  node(id: "VXNlcjox") {
    ... on User {
      email
      privateNotes
    }
  }
}

# Response:
{
  "data": {
    "node": {
      "email": "victim@example.com",
      "privateNotes": "Secret admin notes"
    }
  }
}
```

### cURL reproduction format

Always provide a cURL version for terminal-only reproduction:

```bash
curl -sk -X POST "https://target.com/api/users/123" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"userId": 123, "role": "admin"}'
```

### Python PoC script format

```python
#!/usr/bin/env python3
"""
PoC: IDOR on /api/users/{id}
Tested on: target.com, 2025-01-15
"""
import requests

BASE = "https://target.com"
ATTACKER_TOKEN = "attacker_token_here"
VICTIM_ID = 456

headers = {"Authorization": f"Bearer {ATTACKER_TOKEN}"}

print("[*] Requesting victim's profile via IDOR...")
r = requests.get(f"{BASE}/api/users/{VICTIM_ID}", headers=headers)
print(f"Status: {r.status_code}")
print(f"Response: {r.text}")
```

---

## REDACTION RULES

### What MUST be redacted

| Category | Examples | Format |
|---|---|---|
| Auth tokens | JWT, session cookies, OAuth tokens | `[REDACTED]` |
| API keys | AWS keys, Stripe keys, Google API keys | `[API_KEY-REDACTED]` |
| Passwords | User passwords, DB passwords, service passwords | `[REDACTED]` |
| Secrets | Encryption keys, signing keys, private keys | `[SECRET-REDACTED]` |
| Session IDs | PHPSESSID, JSESSIONID, custom IDs | `[SESSION-REDACTED]` |
| Email addresses | Real victim emails in mass-exfil | `vic***@example.com` |
| Financial data | Full card numbers, bank accounts | `[CARD-REDACTED]` |
| Government IDs | SSN, passport numbers, DL numbers | `[ID-REDACTED]` |
| Internal IPs | Corporate IP addresses | `[IP-REDACTED]` |

### What should NOT be redacted

| Category | Reason |
|---|---|
| HTTP status codes | Proves response type |
| HTTP method and path | Proves attack vector |
| Error messages | Proves the vulnerability |
| Response body structure | Proves data leak scope |
| Non-sensitive headers | Shows attack context |
| Your own test account's PII | Not sensitive; proves who tested |
| Target domain name | Identifying info for the report |
| Non-sensitive endpoint data | Public data shown via vuln is the impact |

### Redaction decision tree

```
Is this a credential or secret? → REDACT
Is this a real user's private PII? → REDACT or partially mask
Is this a production internal IP? → REDACT
Is this the HTTP method/path/status? → KEEP
Is this a non-sensitive header? → KEEP
Is this the response body structure? → KEEP
Is this your own test account data? → KEEP
```

---

## EVIDENCE FOLDER STRUCTURE

Organize evidence per-finding for easy triager review:

```
evidence/
└── [target]-[program]/
    └── YYYY-MM-FindingName/
        ├── README.md                # One-paragraph summary
        ├── request.txt              # Raw HTTP request
        ├── response.txt             # Raw HTTP response
        ├── impact-response.txt      # Response showing third-party data
        ├── screenshot-request.png  # Just the request
        ├── screenshot-impact.png   # Just the response/impact
        ├── screenshot-both.png     # Full Burp window
        ├── burp-export.xml         # Burp message export (redacted)
        └── poc-script.py            # Reproducer script
```

### README.md template

```markdown
# IDOR on /api/users/{id}

## Summary
Authenticated user can read other users' profiles by changing the userId parameter.

## Files in this folder
- `request.txt` — Cross-user request (user 123 → user 456)
- `response.txt` — Response showing victim's PII
- `screenshot-both.png` — Full Burp request/response
- `screenshot-impact.png` — Victim data zoomed
- `poc-script.py` — Reproducible PoC

## Reproduction
1. Login as test user (ID: 123, email: test-123@inbox.test)
2. Send request in request.txt
3. Observe response in response.txt

## Impact
Full PII disclosure for all users: email, phone, address, partial payment data.

## Notes
- Tested 2025-01-15 at 10:30 UTC
- Victim account: ID 456 (redacted in response)
- Token format: JWT HS256 (value redacted)
```

---

## PROGRAM REQUIREMENTS

### HackerOne

```
Required:
- Clear steps to reproduce (numbered)
- Screenshots or video for severity justification
- Exact HTTP request
- Impact statement

Optional but valued:
- Burp project export (if triager requests)
- PoC script
- CVSS score (auto-calculated)
```

### Bugcrowd

```
Required:
- VRT category mapping
- CVSS score (triager adjusts)
- Description, attack scenario, remediation

Format:
- VRT in submission description
- Structured: Vulnerability → Asset → Attack Scenario → Remediation
```

### Intigriti

```
Required:
- Security impact statement
- Technical details with reproduction steps
- Suggested fix

Format:
- Inline technical summary
- Numbered steps, concise
- Screenshots inline in report
```

---

## COMMON EVIDENCE MISTAKES

### Mistake 1: Over-redaction

```
BAD:
Request: POST /api/users/123
Headers: [REDACTED]
Body: [REDACTED]

GOOD:
Request: POST /api/users/123 HTTP/1.1
Headers: Authorization: Bearer eyJhbG... [REDACTED]
Body: {"userId": 123, "email": "victim@example.com"}
```

### Mistake 2: Missing request evidence

```
BAD:
[screenshot of response only]
"This shows the victim's data."

GOOD:
[Full Burp window: request AND response visible]
"Changing userId from 123 to 456 returns victim's data."
```

### Mistake 3: Stale evidence

```
BAD:
Evidence from 30 days ago; app has since changed
Triager tests, finds nothing, closes as N/A

GOOD:
Re-capture evidence within 48 hours of submission
Create new test account if needed
```

### Mistake 4: No redaction

```
BAD:
Submitting a report with live production tokens in the request
Program flags credential exposure in the submission
Your report is held until you sanitize

GOOD:
Redact all tokens before attaching
Verify with a second pass before clicking submit
```

### Mistake 5: Mixed findings

```
BAD:
One zip file with 12 findings, no subfolders
Triager can't find the relevant evidence quickly

GOOD:
One folder per finding, consistent naming
README.md in each folder summarizing the finding
```

---

## CAPTURE CHECKLIST

Before submitting:

- [ ] At least one screenshot per finding
- [ ] Screenshot shows request method, URL, AND response
- [ ] Sensitive tokens/keys redacted
- [ ] Response body proves impact (not just status code)
- [ ] Timestamp visible
- [ ] Own account used (not victim's real credentials)
- [ ] Test account created for this engagement specifically
- [ ] All evidence from the same reproduction session
- [ ] No other engagement's data in evidence files
- [ ] Evidence organized in per-finding folder

---

## FINAL EVIDENCE RULES

1. **Capture before claiming** — never submit without evidence
2. **Redact tokens, not structure** — attack pattern must remain visible
3. **Show request AND response** — one without the other is half a proof
4. **Screenshot proof > text description** — visual evidence is verifiable
5. **Fresh evidence** — re-capture if 48+ hours have passed
6. **Single-finding evidence per folder** — no mixing findings
7. **No production secrets** — report the location, not the value
8. **Structured evidence** — triager finds what they need in 30 seconds
9. **Video for complex attacks** — if screenshots can't show it, video can
10. **Always annotate** — label what the triager is looking at

---

## ADVANCED CAPTURE TECHNIQUES

### Network Traffic Capture with tcpdump/Wireshark

For complex attacks involving multiple systems:

```
WHEN TO USE NETWORK CAPTURE:
- Race condition demonstrations
- Multi-step attack chains spread across multiple requests
- Protocol-level attacks (HTTP/2 smuggling, etc.)
- WebSocket exploitation
- When Burp history needs to be supplemented

TCPDUMP CAPTURE COMMAND:
tcpdump -i eth0 -w evidence.pcap host target.com and port 443

FILTER FOR SPECIFIC CONVERSATION:
tcpdump -r evidence.pcap -n 'host target.com and port 443' -w filtered.pcap

EXPORT AS JSON FOR REPORTS:
tshark -r evidence.pcap -T json > evidence.json

PCAP FORMATTING FOR REPORTS:
- Export as .pcapng (modern format)
- Include in evidence folder alongside screenshots
- Annotate key packets in report text
- Reference packet numbers if triager wants full details
```

### Burp Suite Collaboration Evidence

```
When using Burp Suite Collaborator for OOB testing:

CAPTURE EVIDENCE:
1. Collaborator generates unique subdomain: abc123.burpcollaborator.net
2. App makes DNS lookup or HTTP request to this subdomain
3. Burp Collaborator records the interaction
4. Screenshot: Collaborator interaction log showing:
   - Timestamp
   - Source IP (the target's server IP)
   - Request type (DNS/HTTP)
   - Request details

Screenshot layout for Collaborator:
```
[Burp Collaborator page]
Interaction: DNS lookup for abc123.burpcollaborator.net
Time: 2025-01-15 10:30:45 UTC
Source: 18.245.0.34 (target server)
Subdomain: abc123
Payload context: Blind SQLi via DNS exfil
```
```

### Command-Line Evidence Capture

```
Evidence capture tools for non-Burp workflows:

HTTPie (cleaner than curl for reports):
http --print=HB POST https://target.com/api/users/123 \
  Authorization:"Bearer TOKEN" \
  Content-Type:"application/json" \
  userId:=456

Better for reports because output is clean and copy-pasteable.

Wrk (load testing with evidence):
wrk -t10 -c50 -d30s --script post.lua https://target.com/api/endpoint

Include the Lua script as evidence of testing methodology.

Charles Proxy (alternative to Burp):
→ Similar export format to Burp
→ Right-click → "Copy" → paste into report
→ Good for teams that prefer Charles
```

---

## EVIDENCE PACKAGING BY FINDING TYPE

### Race Condition Evidence Package

Race conditions require special evidence:

```
REQUIRED EVIDENCE FOR RACE CONDITIONS:
1. Multiple parallel requests:
   - Screenshot showing all 20+ requests firing simultaneously
   - OR: terminal showing timing of requests
   - OR: async code showing thread spawning

2. Race outcome demonstration:
   - Final state showing the duplicated effect
   - E.g., coupon applied 5x when only 1 allowed

3. Timing evidence:
   - Before/after timestamps
   - Request timestamps in Burp history
   - Show requests arrived within milliseconds of each other

4. Consistency test:
   - "Ran this test 5 times, race succeeded 3/5 times"
   - OR: "Always succeeds when run this way" (100% reproducible)

VIDEO RECOMMENDED FOR RACE CONDITIONS:
Screen recording showing:
- Request construction
- Burp Repeater window with parallel tab sending
- Timer showing all requests dispatched
- Result showing race effect
```

### Blind Injection Evidence Package

```
Time-based blind SQLi:
1. Baseline timing evidence:
   - 10 baseline requests with timing data
   - Mean and standard deviation visible

2. Payload timing evidence:
   - Same number (10) of payload requests
   - Show consistent 5-second delay

3. Statistical proof:
   - Table showing baseline vs payload timings
   - Force calculator or Python script showing 3σ threshold crossed

4. Extracted data evidence:
   - If you extracted data via blind, show the output
   - Link each data point to its timing test

BOOLEAN-BASED BLIND:
- Show TRUE and FALSE responses side by side
- Highlight the difference (even if subtle)
- Test both conditions at least 3 times each

Format: Screenshot with two responses adjacent, differences annotated.
```

### IDOR Evidence Package

```
IDOR evidence structure:

1. SETUP (brief, but include):
   - Your account: "Attacker account, ID=123, email=attacker@test.com"
   - Victim account: "Different test account, ID=456, email=victim@test.com"

2. BASELINE — your own data:
   - GET /api/users/123 → response showing your data
   - Screenshot or text capture

3. THE ATTACK — cross-user request:
   - GET /api/users/456 (with YOUR session/token)
   - Request: exact HTTP request
   - Response: showing VICTIM's data, not yours

4. THE PROOF — data differs:
   - Annotate response showing victim PII
   - Cross-reference with victim account's own view
   - Prove data is from victim's account

5. BOUNDARY CHECK (optional but valuable):
   - Session B requests own data → 200 with B's data ✓
   - Session B requests A's data → 200 with A's data ✓
   - Both reproduce → strong IDOR confirmation

COMMON IDOR EVIDENCE MISTAKE:
Only showing the victim's data response without showing:
(a) your own data (to prove it's different), OR
(b) the request that triggered the victim data response
```

### SSRF Evidence Package

```
SSRF evidence structure:

1. PRIMITIVE — SSRF works:
   - Request: POST /api/proxy {"url": "http://169.254.169.254/..."}
   - Response showing internal data
   - Path through the SSRF endpoint documented

2. TARGET — internal service:
   - What internal service you reached
   - What port it was on
   - Why that's notable

3. DATA RETURNED:
   - Actual data from the internal service (AWS creds, config, etc.)
   - Redacted: replace real keys with [REDACTED]
   - Show structure: "AWS_ACCESS_KEY_ID: AKIA[REDACTED]"

4. CLOUD METADATA SPECIFIC:
   Step-by-step:
   a) /latest/meta-data/ returns role name (dedup → show role exists)
   b) /latest/meta-data/iam/security-credentials/{role} returns creds
   c) Extract: AccessKeyId, SecretAccessKey, Token, Expiration
   d) Show: token has AWS:* permissions OR list S3 buckets
   e) Gunzipped session token proves active session

5. IMPACT STATEMENT:
   "Server-side credentials allow access to:
   - S3 bucket: company-customer-data (contains PII)
   - Lambda: process-payments (env vars include Stripe keys)
   - DynamoDB: user-sessions table"
```

### XSS Evidence Package

```
STORED XSS EVIDENCE:

1. PAYLOAD STORAGE:
   - Request that creates the payload (POST comment, update profile)
   - Show the payload in the request body

2. PAYLOAD EXECUTION:
   - Screenshot of page where payload executes
   - Browser dev tools showing execution
   - Request from attacker.com server receiving stolen data

3. IMPACT DEMONSTRATION:
   - Show session cookie or other stolen data
   - Annotate: "This is victim's session cookie (look at session ID)"
   - Show: using stolen cookie to access victim account

REFLECTED XSS EVIDENCE:

1. PAYLOAD IN URL:
   - Full URL with payload visible
   - Request in Burp

2. PAYLOAD IN RESPONSE:
   - Response showing payload rendered (not escaped)
   - HTML context visible in source

3. EXECUTION PROOF:
   - Screenshot of browser showing alert() execution
   - Console log showing execution
   - Network request showing data sent to attacker server

DOM XSS EVIDENCE:

1. SINK LOCATION:
   - Show the JavaScript code at the sink (document.write, innerHTML, eval)
   - Source code snippet from page

2. SOURCE TO SINK PATH:
   - Trace from URL fragment (#) or parameter to sink
   - Show the JavaScript that processes the input

3. EXECUTION:
   - Browser screenshot showing execution
   - DevTools > Sources showing the executing code
```

---

## EVIDENCE FORMAT STANDARDS

### Standardized Evidence Markup

Use consistent markup across all reports:

```
EVIDENCE BLOCK FORMAT:

### Evidence: [Vulnerability] — [Step N]

**Request:**
```http
[HTTP request here]
```

**Response:**
```http
[HTTP response here  
or truncated with [REDACTED] for secrets]
```

**Observation:**
[One sentence: what happened and why it matters]

**Timestamp:** [ISO 8601 format: 2025-01-15T10:30:00Z]
**Reproducible:** [Yes/No/With conditions]
**Test Account:** [Description, not actual credentials]
```

### Evidence Annotation Standards

```
ANNOTATION GUIDELINES:

1. Use numbered callouts:
   - ①, ②, ③ for sequential evidence steps
   - A, B, C for parallel evidence streams
   - RED circles for sensitive data locations
   - GREEN circles for attack payload locations
   - YELLOW arrows for data flow direction

2. Annotation placement:
   - Place labels ABOVE or to the LEFT of annotated item
   - Never obscure the evidence with annotations
   - Use high-contrast colors (white text on dark background)

3. Annotation text style:
   - UPPERCASE for labels ("AUTH TOKEN", "VICTIM EMAIL")
   - Keep labels SHORT (2-4 words)
   - Point directly to evidence, don't require reader to search

4. Annotation file naming:
   - screenshot-step1-request.png
   - screenshot-step2-response.png
   - screenshot-impact-annotated.png
```

---

## PROGRAM-SPECIFIC EVIDENCE PACKAGING

### HackerOne Evidence Requirements

```
HACKERONE BEST PRACTICES:

1. Inline vs attachment:
   - Inline: Copy-paste HTTP requests/responses directly in report
   - Better for: Simple findings, quick review
   - Attach: ZIP for complex/video evidence
   - Better for: Complex chains, screen recordings

2. Video guidelines:
   - Under 3 minutes preferred
   - Under 5 minutes MAXIMUM
   - HackerOne plays videos inline
   - Use MP4 (H.264 codec)
   - Under 50MB for direct upload

3. Report attachment organization:
   - One ZIP per report
   - Inside: one folder per finding
   - Include README.md in each folder

4. Version control for reports:
   - HackerOne tracks versions
   - Don't delete and resubmit
   - Edit in place for updates
```

### Bugcrowd Evidence Requirements

```
BUGCROWD BEST PRACTICES:

1. VRT category in submission:
   - Map every finding to VRT taxonomy ON SUBMISSION
   - Use exact VRT category names from Bugcrowd docs
   - Example: "Broken Authentication and Session Management"

2. Structure:
   - Use their template format
   - VRT in description field
   - Remediation as separate section
   - Impact assessment per their severity matrix

3. Attachments:
   - Include .har file if possible (HTTP Archive format)
   - .har is preferred over individual requests
   - Video required for race conditions

4. Disclosure considerations:
   - Bugcrowd disclosure timeline varies by program
   - Check before attaching sensitive info
   - If disclosure in 90 days: evidence can be public later
```

### Intigriti Evidence Requirements

```
INTIGRITI BEST PRACTICES:

1. Inline format:
   - Intigriti prefers inline evidence
   - Keep attachments minimal
   - Include main request/response in report body

2. Language:
   - Can submit in English or local language
   - English preferred for international programs
   - Keep technical terms precise (don't translate IDOR, SSRF, etc.)

3. Proof requirements:
   - More stringent than HackerOne for some programs
   - Minimum: request + response + impact description
   - Preferred: video for complex chains

4. Program notes:
   - Intigriti programs often specify exact evidence format
   - Check program-specific guidelines before submitting
```

---

## EVIDENCE SECURITY AND REDACTION

### Redaction Deep Dive

```
REDACT AS YOU CAPTURE:

Method 1: Burp built-in redaction
- Right-click in message editor
- Select "Redact" for specific headers/values
- Redacted text shows as [redacted]

Method 2: Post-capture regex redaction
```python
import re

REDACT_PATTERNS = {
    'jwt': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+',
    'session_cookie': r'session[=:]\s*[A-Za-z0-9_-]+',
    'api_key': r'key-[A-Za-z0-9]{20,}',
    'aws_key': r'AKIA[A-Z0-9]{16}',
    'authorization': r'Bearer\s+[A-Za-z0-9._-]+',
    'set_cookie': r'Set-Cookie:\s*[^;]+',
}

def redact(text):
    for pattern_name, pattern in REDACT_PATTERNS.items():
        text = re.sub(pattern, f'[{pattern_name.upper()}-REDACTED]', text)
    return text
```

REDACTION VERIFICATION CHECKLIST:
[ ] All bearer tokens redacted
[ ] All session cookies redacted  
[ ] All API keys/secret keys redacted
[ ] All passwords redacted
[ ] Production internal IPs redacted
[ ] Real victim PII partially masked or notes added
[ ] Your own test account data kept (proves you're a tester)
[ ] Target domain name KEPT (necessary for triager)
[ ] HTTP methods, paths, status codes KEPT
[ ] Non-sensitive headers KEPT (show context)
```

### Sensitive Data Handling

```
HANDLING VICTIM PII IN EVIDENCE:

The victim accounts used in testing are YOUR test accounts (per engagement rules).
But production responses often contain real victim data.

Rule: DO NOT harvest or exfiltrate production user data.

In evidence:
- Show the RESPONSE STRUCTURE proves other user's data
- You can quote fields: "Response returned 'email': 'victim@example.com'"
- Don't screenshot 100 user records "to show scope"
- Request permission from program if bulk data appears in any response

If you accidentally see sensitive data:
1. Document what you saw
2. Report it to the program immediately
3. Don't publish or share that specific data
4. Use anonymized examples in your report
```

---

## EVIDENCE QUALITY AUDIT

### Self-Audit Before Submission

Run this audit on every evidence package:

```
REPRODUCIBILITY AUDIT:
[ ] Can a third party reproduce from the evidence alone?
[ ] Is every request copy-pasteable?
[ ] Are redactions clearly explained?
[ ] Is the attack path clear from evidence alone?

POTENTIAL TRIAGER QUESTIONS:
[ ] How did you get the token? → Setup steps in evidence or report
[ ] What account was this on? → Account description included
[ ] When was this tested? → Timestamp in evidence
[ ] What version of the app? → Version noted
[ ] Does this still work? → Fresh capture (within 48h)

TAMPERING CHECKLIST:
[ ] No evidence appears modified
[ ] Response matches what Burp captured (same status, similar body size)
[ ] Timestamps are consistent (no impossible time gaps)
[ ] Request IDs/trace IDs present if app uses them
[ ] Sequential numbering preserved if capturing multi-step
```

### Evidence Integrity Verification

```
HASHING FOR EVIDENCE INTEGRITY:

Generate SHA-256 hashes of all evidence files before submission:
```bash
sha256sum evidence/* > evidence-hashes.txt
```

Example output:
```
a3f2c1...  evidence/request.txt
b7d4e9...  evidence/response.txt
c1e8f2...  evidence/screenshot-request.png
```

Include evidence-hashes.txt in your submission so:
- Triager can verify files weren't modified en route
- You can prove you captured the evidence at the stated time
- Chain of custody is established

TIMESTAMP VERIFICATION:
Include metadata on screenshots:
```bash
# exiftool to check/verify timestamps
exiftool screenshot-request.png
# Shows: Create Date, Modify Date, etc.

# If timestamps are missing or wrong, fix before submitting
# Some tools strip Exif data by default
```
```

---

## FINAL EVIDENCE HYGIENE RULES

11. **Capture raw before manipulating** — raw Burp export is your source of truth
12. **Every finding gets at least Level 3 evidence** — raw request + response text
13. **Annotate for triager speed** — label what matters in 2 seconds of viewing
14. **Fresh evidence for every submission** — don't reuse old screenshots
15. **Single finding per folder** — triager should find what they need in 30 seconds
16. **Hash your evidence files** — prove integrity and timestamp
17. **Redact secrets, not structure** — the attack pattern must remain visible
18. **Include setup context** — "test account Alice, ID 123, created Jan 15"
19. **Request > Screenshot** — screenshot is supplementary, request is primary
20. **No production credential values** — report the location, never the key

---

## EVIDENCE COLLECTION PROTOCOLS BY EXPLOITATION TYPE

### Proof-of-Concept Development Standards

The evidence collection process differs by vulnerability class. Each requires specific evidence types to prove impact:

**SQLi Evidence Pyramid:**
1. Error message containing SQL syntax → INFORMATIVE (soft proof)
2. Boolean blind differential response → LOW-MEDIUM (code analysis required)
3. Time-based blind with statistical proof → MEDIUM (proves injection point)
4. UNION-based extraction of real data → HIGH (proves data access)
5. Full database access or OS-level execution → CRITICAL

**IDOR Evidence Requirements:**
1. Status 200 on other user's resource → INSUFFICIENT alone
2. Response showing different identifying data → MINIMUM (email mismatch proves it)
3. Response showing financial/PII data → HIGH (scope of damage)
4. Write/delete capability via IDOR → escalates one severity level

**SSRF Evidence Requirements:**
1. 200 response on internal endpoint → INDICATOR only
2. Internal hostname/IP returned in response → MEDIUM
3. Service banner or application output → MEDIUM-HIGH
4. AWS credentials, Redis keys, JWT tokens → CRITICAL
5. Cloud compromise (S3 access, Lambda execution) → CRITICAL

### Evidence Chain Documentation

Every chained exploitation requires evidence for each transition:

```
Chain: IDOR → Email Change → Password Reset → ATO

Evidence requirements per step:
Step 1 (IDOR): Cross-user email change request + response
Step 2 (Email change): Request/response showing email modified to attacker's address
Step 3 (Password reset): Request to reset password + response
Step 4 (ATO): Request using reset link + confirmation of new password access

Step 1: Request/Screenshot/Response body
  - Show: Original userId parameter vs modified victim userId
  - Show: Response confirming email change

Step 2: Email server evidence
  - Burp response showing reset request to attacker's email
  - Or: Email server log entry (if you control attacker.com mail)

Step 3: Password change confirmation
  - Request: POST /api/password-reset with token
  - Response: 200 with "password updated"

Step 4: Login proof
  - Request: POST /api/auth/login with new password
  - Response: 200 with new session token
  - Screenshot: Dashboard accessible with new session
```

---

## ADVANCED EVIDENCE FORMATTING

### Standardized JSON Evidence Blocks

For API-heavy targets, structured JSON evidence helps triagers parse findings:

```json
{
  "evidence_type": "idor_exploitation",
  "timestamp": "2025-01-15T10:30:00Z",
  "test_environment": {
    "tester_account": {
      "id": "123",
      "role": "user",
      "email": "tester-123@inbox.test"
    },
    "victim_account": {
      "id": "456",
      "role": "user",
      "email": "victim-456@inbox.test"
    }
  },
  "steps": [
    {
      "step": 1,
      "description": "Baseline: Request own user data",
      "request": {
        "method": "GET",
        "path": "/api/users/123",
        "headers": {...},
        "body": null
      },
      "response": {
        "status": 200,
        "body_summary": "Own user data returned"
      }
    },
    {
      "step": 2,
      "description": "Attack: Request victim's data via IDOR",
      "request": {
        "method": "GET",
        "path": "/api/users/456",
        "headers": {...},
        "body": null
      },
      "response": {
        "status": 200,
        "body_summary": "VICTIM'S data returned with tester's token",
        "sensitive_fields": ["email", "phone", "address"]
      }
    }
  ],
  "impact_assessment": {
    "data_type": "PII",
    "estimated_affected_users": "50,000+",
    "attack_scenario": "Any authenticated user can enumerate all user PII"
  }
}
```

### cURL Command Generation for Reports

Always provide cURL commands for reproducibility:

```bash
# Step 1: Baseline (own data)
curl -sk -X GET "https://target.com/api/users/123" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -H "Content-Type: application/json"

# Step 2: IDOR attack (victim data with attacker token)
curl -sk -X GET "https://target.com/api/users/456" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -H "Content-Type: application/json"

# Step 3: Verify with victim account (should also see own data)
curl -sk -X GET "https://target.com/api/users/456" \
  -H "Authorization: Bearer VICTIM_TOKEN" \
  -H "Content-Type: application/json"
```

### HTTPie Command Generation (Cleaner Alternative)

For teams that prefer HTTPie for readability:

```bash
# Aggressive flag shows full request/response
http --verbose GET https://target.com/api/users/456 \
  Authorization:"Bearer ATTACKER_TOKEN" \
  Content-Type:"application/json"

# POST with JSON body
http --verbose POST https://target.com/api/users \
  Authorization:"Bearer ATTACKER_TOKEN" \
  Content-Type:"application/json" \
  userId:=456 email:=attacker@evil.com
```

---

## EVIDENCE FOR SPECIAL CASE FINDINGS

### Deserialization Evidence

For deserialization findings, evidence focuses on payload generation:

```
PHP Deserialization:
1. Original serialized string (normal data)
2. Modified serialized string (with magic method chain)
3. PHP code showing the dangerous sink (unserialize($input))
4. Output showing command execution (id, whoami output)

Java Deserialization:
1. ysoserial command used to generate payload
2. The generated payload (base64 encoded)
3. HTTP request sending payload to endpoint
4. jd-gui or javap output showing gadget chain classes
5. Proof of execution (DNS callback, file write, command output)

Python Pickle:
1. pickle.dumps() showing normal serialization
2. pickle.loads() with malicious payload
3. The __reduce__ method proving code execution
4. Output from RCE (id command result)
```

### Prototype Pollution Evidence

```
Steps to evidence:
1. Initial request with normal property setting
2. Request with __proto__ or constructor.prototype payload
3. Evidence that prototype was modified:
   - JavaScript execution in browser console
   - Modified behavior in subsequent requests
   - Server-side prototype reflected in response

Key distinction:
- If __proto__ modifies client-side JS: browser-based finding
- If __proto__ modifies server-side Node.js: server-side RCE
- Evidence: Show the affected runtime and the modification result
```

### Cache Poisoning Evidence

```
Cache poisoning requires specific evidence trail:

1. Normal request (baseline):
   GET /?cb=12345 → 200 with content A

2. Poison request:
   GET /?x=<script>alert(1)</script> → 200 with poisoned content

3. Victim request (showing poisoned cache):
   GET /?cb=67890 → 200 with SAME poisoned content (from cache)

Key evidence:
- Both requests return identical response despite different parameters
- Response headers showing cached version (X-Cache: HIT)
- Time gap showing poison request happened before victim request
- Un-keyed parameter reflected in cached response

Cache key analysis:
Show which headers/parameters ARE in the cache key vs which are NOT:
Cached: path, host, cookie, Accept-Encoding
Not cached: arbitrary query parameters, X-Forwarded-Host
```

### Insecure Direct Object Reference (IDOR) Advanced Evidence

```
For complex IDOR scenarios:

Mass IDOR:
1. Request for 1 user's data → 200 with user's PII
2. Request for 50 user IDs in loop → 50 responses, each with different PII
3. Summary table: "Request /users/ID returned data for:
   ID 1: alice@example.com
   ID 2: bob@example.com
   ID 3: carol@example.com..."

Wildcard IDOR:
1. Request /users/* → returns ALL user records
2. Count: 15,000 user records returned
3. Sample: Show first 3 records

UUID IDOR:
1. Show the UUID format is guessable/predictable
2. Show that app uses sequential UUIDs or user-ID-derived UUIDs
3. Show that changing last 8 chars returns different user's data

GraphQL IDOR:
1. Introspection query showing the schema
2. node(id: "VXNlcjox") query returning user 1 data
3. node(id: "VXNlcjoy") query returning user 2 data
4. Base64-decode showing ID encodes to sequential number
```

---

## EVIDENCE ORGANIZATION FOR COMPLEX PROGRAMS

### Multi-Finding Evidence Organization

For programs with volume submissions, organize evidence at scale:

```
findings/
├── README.md (engagement summary)
├── finding-001-idor-users/
│   ├── README.md (finding-specific)
│   ├── evidence/
│   │   ├── step-1-own-data/
│   │   │   ├── request.md
│   │   │   ├── response.md
│   │   │   └── screenshot.png
│   │   ├── step-2-cross-user/
│   │   │   ├── request.md
│   │   │   ├── response.md
│   │   │   ├── screenshot.png
│   │   │   └── annotated-impact.png
│   │   └── step-3-victim-confirm/
│   │       ├── request.md
│   │       └── response.md
│   └── poc.py
├── finding-002-xss-comments/
│   └── ...
└── finding-003-chain-idor-ato/
    ├── README.md
    ├── evidence/
    │   ├── step-1-idor/
    │   ├── step-2-email-change/
    │   ├── step-3-reset-request/
    │   └── step-4-login/
    └── chain-poc.py
```

### Bulk Evidence Export

When submitting multiple findings at once:

```bash
# Create organized evidence package
find . -name "*.png" | sort > screenshots.txt
find . -name "*.txt" | sort > text-evidence.txt
find . -name "*.py" | sort > poc-scripts.txt

# Generate file manifest with hashes
Get-ChildItem -Recurse | 
  Get-FileHash -Algorithm SHA256 | 
  Export-Csv evidence-manifest.csv -NoTypeInformation

# Compress with metadata
Compress-Archive -Path evidence/* -DestinationPath findings-bundle.zip
```

---

## EVIDENCE PRESENTATION IN REPORTS

### Report Structure with Evidence

```markdown
# [Bug Class] in [Endpoint] allows [Actor] to [Impact]

## Summary
[2-3 sentence overview of vulnerability and impact]

## Affected Asset
- **Asset:** target.com (subdomain: api.target.com)
- **Scope basis:** Listed in program scope 2025-01-10
- **Endpoint:** /api/users/{id}
- **HTTP method:** GET

## Vulnerability Details
[Technical description — 3-5 sentences]

### Root Cause
[What's wrong in the code or architecture]

## Reproduction Steps

### Step 1: Setup test accounts
```
Account A (attacker): ID=123, email=attacker@inbox.test
Account B (victim): ID=456, email=victim@inbox.test
Both created specifically for this engagement
```

### Step 2: Request own data (baseline)
[Request block + response block]

### Step 3: Request victim data (attack)
[Request block + response block]
**Request:**
```
GET /api/users/456 HTTP/1.1
[full request]
```
**Response:**
```json
{
  "id": 456,
  "email": "victim@inbox.test",
  "name": "Victim User",
  "phone": "555-0123"
}
```

## Impact
[Quantified impact statement]

## Remediation
[Specific code-level fix]

## References
- OWASP API Security Top 10: BOLA (Broken Object Level Authorization)
- CWE-639: Authorization Bypass Through User-Controlled Key
- CVE-2024-XXXXX (similar vulnerability in [related system])

---

## Evidence Attachments
- `evidence/step-2-request-response.png` — Full Burp window
- `evidence/step-3-impact.png` — Zoom on victim data
- `evidence/poc-script.py` — Reproducer script

[Attach as ZIP to report]
```

---

## FINAL EVIDENCE RULES (Expanded to 30)

10. **Always annotate** — label what the triager is looking at
11. **Capture raw before manipulating** — raw Burp export is your source of truth
12. **Every finding gets at least Level 3 evidence** — raw request + response text
13. **Annotate for triager speed** — label what matters in 2 seconds of viewing
14. **Fresh evidence for every submission** — don't reuse old screenshots
15. **Single finding per folder** — triager should find what they need in 30 seconds
16. **Hash your evidence files** — prove integrity and timestamp
17. **Redact secrets, not structure** — the attack pattern must remain visible
18. **Include setup context** — "test account Alice, ID 123, created Jan 15"
19. **Request > Screenshot** — screenshot is supplementary, request is primary
20. **No production credential values** — report the location, never the key
21. **Show BOTH sides** — the vulnerable request AND the compromised response
22. **Timestamp everything** — ISO 8601 format for all evidence
23. **Request MUST be copy-pasteable** — with [REDACTED] markers, not blank headers
24. **Annotate sensitive data** — highlight victim data in response without exposing full PII
25. **Include baseline evidence** — what your account sees vs what victim's account returns
26. **Document evidence chain** — each attack step has its own evidence block
27. **Test account provenance** — use accounts created for THIS engagement only
28. **Re-capture if 48h passed** — apps change, cache expires, tokens rotate
29. **Triple-check redactions** — run the redacted request through — it should still make sense
30. **The triager's time is valuable** — organize evidence so they find proof in 3 clicks or less

---

## EVIDENCE CAPTURE BEST PRACTICES SUMMARY

```
PRE-CAPTURE:
1. Clear context — know what you're testing and why
2. Set up dedicated test accounts for this finding
3. Ensure Burp/Logger++ is active and logging
4. Note the starting timestamp

DURING CAPTURE:
1. Send one request at a time (for clean evidence)
2. Annotate immediately after capture
3. Screenshot: URL, request, response all in one view
4. Save to structured folder (per finding)

POST-CAPTURE:
1. Verify evidence is readable and complete
2. Apply redactions
3. Hash evidence files
4. Write evidence README
5. Package for submission
6. Double-check no other engagement data in files
7. Attach to report

AFTER-SUBMISSION:
1. Keep evidence archive for 90 days (disclosure period)
2. Respond to triager requests for additional evidence promptly
3. Update evidence if triager reports reproduction failure
4. Add successful evidence patterns to personal library
```
