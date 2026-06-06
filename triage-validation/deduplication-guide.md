---
name: deduplication-guide
description: Deduplication workflow for bug bounty hunters. Covers how to search for prior disclosures, how to confirm a finding is unique, what to do when a similar finding exists, and how to re-submit with a new angle. Use when you think you found a bug and need to verify it hasn't already been reported or disclosed. Chinese trigger: 去重、deduplication、重复漏洞、disclosed、hacktivity、重复提交
---

# Deduplication Guide

How to verify your finding is unique before submitting.

---

## DEDUPLICATION PHILOSOPHY

```
DEDUPLICATION LIFECYCLE:
1. SEARCH — Check all prior disclosure sources
2. COMPARE — Map the disclosed bug vs your finding
3. DECIDE — Is yours same root cause? Same impact?
4. ADAPT — If similar but different, find your unique angle
5. DOCUMENT — Note your search results in the report
```

### Deduplication rules

| Scenario | Action |
|---|---|
| Identical endpoint, identical vuln class, identical impact | **KILL** — duplicate |
| Identical endpoint, same class, DIFFERENT impact angle | Proceed if angle is genuinely distinct and proof is fresh |
| Same endpoint, different vuln class | Proceed (e.g., IDOR + XSS on same endpoint are separate bugs) |
| Same endpoint, same impact, different HTTP method | Proceed if different method = different attack surface |
| No disclosure found, similar pattern exists | Proceed — absence of disclosure ≠ duplicate |

---

## SEARCHING DISCLOSED REPORTS

### HackerOne Hacktivity Search

```
Search strategies:
1. Program name + vuln class: "target.com XSS"
2. Endpoint path: "target.com /api/users"
3. Bug class keyword: "target.com IDOR"
4. Specific parameter: "target.com userId"

Filter tips:
- Sort by most recent
- Filter by severity
- Read the FULL report, not just the title
- Note the disclosed date and researcher name
```

**Advanced Hacktivity search operators:**
```
site:hackerone.com "target.com" "XSS" "stored"
site:hackerone.com "target.com" "/api/users" "IDOR"
site:hackerone.com "target.com" "critical"
site:hackerone.com "target.com" "admin"

In HackerOne UI filters:
- Report state: Resolved (shows fixed vulns)
- Severity: Critical, High, Medium, Low
- Sort by: Most recently disclosed
```

### Bugcrowd Disclosure Search

```
Bugcrowd URL patterns:
https://bugcrowd.com/en/disclosures

Search by:
- Company name (full and abbreviated)
- Vulnerability type (from Bugcrowd VRT taxonomy)
- Asset name
- Researcher name

Bugcrowd-specific tips:
- Look for "Vulnerability Co-occurrence" disclosures (multiple bugs in one report)
- Read the VRT category carefully; some disclosures report multiple VRT categories
- Check disclosure date: very old disclosures may not cover current codebase
```

### Intigriti Disclosure Platform

```
URL: https://www.intigriti.com/en/disclosures

Intigriti-specific tips:
- Disclosures include detailed PoC steps
- Read the "Attack Vector" section to compare with yours
- Note: Intigriti disclosures often include fix recommendations
- Check researcher names: repeat researchers tend to specialize in specific vuln classes
```

### GitHub Issues Search

```
For open-source targets:
1. Go to target/repo-name
2. Issues → Search: SECURITY ENDPOINT_NAME
3. Issues → Search: is:closed is:issue ENDPOINT_NAME security
4. PRs mentioning security fixes
5. CHANGELOG.md for security changes

Patterns indicating disclosure:
- Issue closed with fix: "Fixed in v2.3.1"
- Issue labeled "security" or "security-fix"
- Issue marked as duplicate → follow to original
- Commit message: "security: prevent XSS in comment field"
```

### GitHub Security Advisories

```
GitHub-specific security disclosures:
URL: https://github.com/target/repo/security/advisories

Search:
1. Global search: "target repo security advisory"
2. On GitHub: target/repo → Security → Advisories
3. Check "GHSA" identifiers for public advisories

Advisories often include:
- CVE IDs
- Fixed versions
- Affected components
- Credit to researcher

This is the most authoritative disclosure source for open-source targets.
```

### Google Dorks for Disclosures

```
site:hackerone.com "target.com" "XSS"
site:hackerone.com "target.com" "/api/users"
site:bugcrowd.com "target.com"
site:intigriti.com "target.com"
site:medium.com "target.com" "bug bounty"
site:github.com "target.com" "security" "fixed"
site:medium.com "target.com" "security"
```

### Shodan/Censys for Prior Disclosure Context

```
Sometimes disclosed reports mention CVE numbers that can be cross-referenced:
- CVE: https://cve.mitre.org/
- NVD: https://nvd.nist.gov/
- Exploit-DB: https://www.exploit-db.com/

If a disclosure mentions CVE-2024-XXXX, check NVD for:
- Affected versions
- Fixed versions
- Whether your target's version is affected

CVE presence often indicates broader disclosure; the triager may know about it.
```

---

## COMPARING YOUR FINDING TO DISCLOSURES

### Comparison dimensions

| Dimension | If SAME → likely duplicate | If DIFFERENT → likely unique |
|---|---|---|
| Vulnerability type | Same (e.g., both IDOR) | Different class |
| Endpoint | Exact same path | Different path or parameter |
| Impact | Same data accessible | Different data type or scope |
| Attack vector | Same request shape | Different HTTP method or injection point |
| Time discovered | Was recent (months ago) | Was years ago; app changed since |
| Fix applied | Fixed in specific version | Not fixed or partially fixed |
| Your proof | Body identical to disclosed proof | You have new PoC or extended impact |

### Step-by-step comparison procedure

```
Step 1: Read the disclosure title
- Same vuln class + endpoint? → deep comparison needed
- Different vuln class? → proceed (different bug)

Step 2: Read the disclosure description
- Same root cause? (e.g., missing authorization check)
- Same attack path? (e.g., changed userId in GET request)
- Same impact? (e.g., read PII)

Step 3: Read the disclosure fix
- If the fix also addresses your vector → same root cause
- If the fix leaves your vector open → different bug

Step 4: Test on current version
- The disclosed bug may have been fixed in version X
- Your target may be on version X+1 where it regressed
- OR your target may never have been patched (different deployment)
- Both scenarios: this is a NEW finding of the same type
```

### "Same bug, different PoC" trap

```
Common trap: You found the same IDOR but with a different HTTP method.

Check: Is the underlying access control failure the same?
- YES (both GET /api/users/123 and PUT /api/users/123 return victim data via IDOR):
  Root cause is the same missing authorization check.
  One report covering both methods is correct.
- NO (GET returns PII that PUT cannot access, or vice versa):
  Different data paths, different reports acceptable.

How to decide: Ask "does the program's fix for the disclosed bug also fix mine?"
If YES → same root cause, one report.
If NO → different root cause, separate report.
```

### "Fixed but regressed" pattern

```
Pattern: Bug fixed in version X, reappeared in version Y.

Action: Search for re-disclosure policy on the program.
Many programs allow re-reporting of regressed bugs.

Evidence to include:
- Link to original disclosure
- Version where it was fixed
- Proof that it works again in current version
- Note: "This finding was previously disclosed as [link] and fixed in vX.Y.Z. It has regressed in the current version."

Programs that explicitly allow regression reports:
- HackerOne: Yes, with evidence of regression
- Bugcrowd: Usually yes, check program rules
- Intigriti: Usually yes
```

---

## WHAT TO DO WHEN DUPED

### Option 1: Kill it and move on

- You wasted 30 minutes on a known issue
- Cost is low; treat it as reconnaissance practice
- Note the disclosure in your log so you don't re-check it
- Time saved can be spent on new attack surface

### Option 2: Find a new angle (best option)

Ask: "What else can I do with this primitive?"

| Disclosed primitive | New angle opportunities |
|---|---|
| IDOR on GET /users/{id} | Try PUT/DELETE; try header X-User-ID; try GraphQL node() |
| XSS on profile bio | Target admin view; CSRF chain; stored XSS via SVG upload |
| SSRF to internal host | Chain with gopher to Redis; chain with redirect bypass |
| Open redirect /?next= | Chain to OAuth; chain to subdomain takeover |
| Rate limit bypass on login | Chain to OTP brute force; check admin login separately |

### Option 3: Report as regression

```
If you find a previously disclosed bug is live again:
1. Reference the original disclosure URL
2. Provide fresh proof (new screenshots, new PoC)
3. Note the regression and version info
4. Program may award again (varies by policy)

Example note:
"This finding was disclosed as #12345 on 2023-03-15 and fixed in v2.1.
It has regressed in the current v2.4 deployment. New PoC provided above."
```

### Option 4: Combine with chain

```
If the primitive is disclosed but the chain isn't:
- Original: IDOR on GET /api/users/{id} (disclosed, paid out)
- Your chain: Same IDOR + password reset endpoint = ATO
- If the chain wasn't in the original disclosure: NEW finding

Example:
Disclosed: "User A can read User B's email via IDOR"
Your chain: "User A can change User B's email via IDOR, then request password reset, then change User B's password → full ATO"

If the chain is genuinely new, submit it as a new finding with reference to the original.
```

---

## DEDUPLICATION SOP (Standard Operating Procedure)

Use this checklist before submitting ANY finding:

```
[ ] 1. Search HackerOne Hacktivity for exact endpoint
[ ] 2. Search Bugcrowd disclosures
[ ] 3. Search Intigriti disclosures
[ ] 4. Search GitHub issues for target repo
[ ] 5. Search GitHub security advisories
[ ] 6. Search program's disclosed reports page
[ ] 7. Google: "TARGET ENDPOINT bug bounty"
[ ] 8. Check CVE databases if version disclosed
[ ] 9. Read the 3 most similar disclosures IN FULL
[ ] 10. Document: "Similar disclosure found: [link] — difference is [X]"
[ ] 11. If no match found: proceed
[ ] 12. If same bug found: look for new angle or kill
[ ] 13. Note dedup search in report notes for triager evidence
[ ] 14. Timestamp your search (when you checked)
```

### Deduplication evidence in report

At the bottom of your report notes (or in a private comment), include:

```markdown
## Deduplication note

Searched HackerOne Hacktivity, Bugcrowd, GitHub issues on YYYY-MM-DD.
Closest disclosure: [researcher name], [date], [link].
Difference: Their report covers GET /api/users/{id} returning 200.
This report covers PUT /api/users/{id} allowing profile modification.
Different HTTP method, different attack surface, different impact.
No disclosed report covers the write-only IDOR path.
```

---

## PROGRAM-SPECIFIC DEDUPLICATION BEHAVIOR

| Program type | Deduplication behavior | Tips |
|---|---|---|
| HackerOne public | Full Hacktivity public | Search is mandatory |
| HackerOne private | Disclosures visible to approved researchers | Join program first, then search |
| Bugcrowd | Disclosure page available | Check VDP-vs-paid-policy |
| Intigriti | Rich disclosure platform | Detailed PoCs; read carefully |
| Intigriti private | Disclosures on platform after resolution | Search after acceptance |
| Private program | No public disclosures | Trust uniqueness; document your search |
| Open-source | GitHub + advisories | Fastest to search; most detailed |

---

## FALSE DEDUPLICATION SIGNALS

These are NOT duplicates even if they look similar:

| Pattern | Why NOT a duplicate |
|---|---|
| Same endpoint, self-XSS vs stored XSS | Different class, different impact |
| Same endpoint, reflected XSS vs stored XSS | Different class |
| Same parameter, GET vs POST | Different vector |
| Same endpoint, missing auth vs IDOR | Different root cause |
| Same SSRF target, DNS callback vs data exfil | Different proof and impact |
| Same CSRF endpoint, no token vs token bypass | Different vuln class |
| Same endpoint, fixed in v2, appears in v3 | Regression — may be valid re-report |
| Same endpoint, disclosed on different subdomain | Different asset; new report |

---

## FINDING NEW ANGLES AFTER DEDUP

### Angle-finding framework

When you discover a similar disclosure, run this mental checklist:

```
1. Are there OTHER HTTP methods on the same endpoint?
   - disclosed: GET /api/users/{id} → IDOR
   - new: PUT /api/users/{id} → write IDOR
   - new: DELETE /api/users/{id} → delete IDOR
   - new: PATCH /api/users/{id} → partial write IDOR

2. Are there OTHER parameters on the same endpoint?
   - disclosed: ?id= parameter
   - new: ?user_id= header parameter
   - new: JSON body {userId: X}
   - new: X-Original-User-ID header

3. Does it affect OTHER user roles?
   - disclosed: IDOR on regular user data
   - new: IDOR on admin data (different endpoint or same)
   - new: IDOR on system-level data

4. Can you chain it to escalate?
   - disclosed: IDOR on email read
   - new: IDOR on email change → password reset → ATO
   - new: IDOR on 2FA disable → account takeover

5. Does it work on OTHER account types?
   - disclosed: Works on free accounts
   - new: Works on enterprise accounts
   - new: Works on admin accounts (privilege escalation)

6. Can you access OTHER data types?
   - disclosed: Can read name and email
   - new: Can read payment data
   - new: Can read private messages
   - new: Can read internal notes
```

### Specific angle templates

**IDOR angle templates:**
```bash
# Template 1: HTTP method swap
Original: GET /api/users/{id}
New angle: PUT /api/users/{id} with {"role": "admin"}

# Template 2: Parameter location swap
Original: ?userId=456 in query
New angle: {"userId": 456} in JSON body
New angle: X-User-ID: 456 in header

# Template 3: Batch parameter abuse
Original: /api/users/{id} (single)
New angle: /api/users?ids=1,2,3,4,5 (batch - mass exfil)

# Template 4: GraphQL node enumeration
Original: REST endpoint IDOR
New angle: GraphQL {node(id: "VXNlcjox")} with brute-force IDs
```

**XSS angle templates:**
```bash
# Template 1: Storage location change
Original: XSS in profile bio (self-view only)
New angle: XSS in comment (any user views)
New angle: XSS in support ticket (admin views)

# Template 2: Context change
Original: Reflected XSS in search results
New angle: Stored XSS in search history
New angle: DOM XSS via #fragment

# Template 3: Trigger change
Original: XSS on click
New angle: XSS auto-executes (onload, onerror)
New angle: XSS via WebSocket message
```

**SSRF angle templates:**
```bash
# Template 1: Protocol change
Original: HTTP SSRF to 169.254.169.254
New angle: Gopher:// to Redis → RCE
New angle: File:// /etc/passwd

# Template 2: Target change
Original: SSRF to AWS metadata
New angle: SSRF to internal admin panel
New angle: SSRF to Elasticsearch
New angle: SSRF to Redis with session data

# Template 3: Chain path
Original: SSRF to internal host
New angle: SSRF → metadata → AWS creds → S3 exfil
```

---

## ADVANCED DEDUP TECHNIQUES

### Using Google Cache for Disclosures

```
Sometimes Hacktivity is blocked or slow. Use Google cache:
cache:https://hackerone.com/reports/123456

Or use the Wayback Machine:
https://web.archive.org/web/2024*/https://hackerone.com/reports/123456
```

### Automated Disclosure Monitoring

```
Set up alerts:
- HackerOne: Follow target program, enable notifications
- GitHub: Watch target repo, enable security alerts
- Google Alerts: "target.com" + "bug bounty" + "XSS/IDOR/SSRF"
- Twitter/X: Follow security researchers who report on target

This way you know about disclosures as they happen, not after.
```

### Proactive Dedup: Check Before Testing

```
Before starting deep testing on a program:
1. Read the last 20 disclosed reports
2. Note: vuln classes already reported
3. Note: endpoints already covered
4. Note: severity awarded
5. Note: patterns that programs pay for vs don't

This 30-minute investment prevents hours of duplicate testing.
```

---

## DEDUP COMMON MISTAKES

### Mistake 1: Declaring dup based on title only

```
BAD: "I see an IDOR report → my IDOR is duplicate"
GOOD: Read both full reports; compare endpoint, impact, and fix

Titles often don't capture the full nuance:
- "IDOR on /api/users" could mean 10 different IDOR variants
- "XSS on checkout" could mean stored, reflected, or DOM
```

### Mistake 2: Ignoring the fix

```
Disclosed bug was fixed with: "Added user_id check on GET /api/users/{id}"
Your bug: Same endpoint but POST /api/users/{id}

Question: Does the disclosed fix also cover POST request?
If NO → this is a NEW finding (different code path)
If YES → same root cause, duplicate
```

### Mistake 3: Not checking regressions

```
Many fixes are incomplete. A disclosed bug fixed in v2.1 may:
1. Reappear in v2.3 (code refactor removed the fix)
2. Work in a different subdomain not tested originally
3. Apply to a different role than originally tested

Always re-test disclosed bugs on the current version before declaring dup.
```

### Mistake 4: Self-suppressing valid findings

```
Pattern: "Similar finding exists" → self-KILL without verification

Reality: Your finding may be genuinely different
Cost of self-dedup: potential bounty
Cost of duplicate submission: N/A, slight reputation hit

Decision framework:
- If you can articulate 3 specific differences → submit with notes
- If you can only articulate 1 vague difference → likely dup
- When uncertain: submit with clear dedup justification; let triager decide
```

---

## FINAL DEDUPLICATION RULES

1. Search ALL sources — not just HackerOne
2. Read FULL disclosures, not just titles
3. Compare root cause, not just symptom
4. Check for regressions — disclosed ≠ fixed forever
5. Look for new angles — same primitive, different exploitation path
6. Document your search timestamp and results
7. When uncertain, submit with justification — let triager decide
8. Self-suppression costs more than duplicate rejection
9. Re-submitting with new angle is professional; re-submitting identical is noise
10. A good dedup note in your report accelerates triager approval

---

## ADVANCED DEDUPLICATION TECHNIQUES

### Pattern Matching Against Disclosures

When comparing your finding to disclosed reports, use a structured comparison template:

```
COMPARISON TEMPLATE:

Dimension                | Your Finding     | Disclosed Report    | Same/Different?
------------------------|------------------|---------------------|----------------
Vulnerability class     | [class]          | [class]             |
Affected endpoint       | [path]           | [path]              |
HTTP method             | [GET/POST/etc]   | [GET/POST/etc]      |
Injection point         | [param/header]   | [param/header]      |
Impact type             | [what attacker gets] | [what they got]  |
Attack prerequisites    | [what attacker needs] | [what they needed] |
Technical root cause    | [e.g., missing auth check on line 47] | [e.g., missing ID check] |
Fix applied             | [if known, what they fixed] | [fix from report] |

RESULT: If ALL dimensions same → duplicate. Any dimension different → new finding.
```

### "Same Bug, Different Payload" vs "Different Bug"

```
CRITICAL DISTINCTION:

Same bug (don't re-report):
- Same missing auth check
- Same endpoint affected
- Different payload reaches the same broken check
Example: GET /api/users/1 uses get_user_by_id() without auth
         PUT /api/users/1 also uses get_user_by_id() without auth
         → SAME root cause, ONE report

Different bug (report separately):
- Different code paths affected
- Different root causes
Example: GET /api/users/1 has no auth check (root cause: missing middleware)
         PUT /api/users/1 has auth check BUT bypasses it via header (root cause: header override)
         → TWO different root causes, TWO reports
```

### Program-Specific Disclosure Behavior

```
HACKERONE:
Disclosed = visible to all researchers
Most thorough disclosure platform
Disclosure happens ~90 days after resolution for most programs
Pay-to-see model: you can see it for free after disclosure

BUGCROWD:
Variable disclosure timelines (30-90 days)
Some programs NEVER disclose (aggressive programs)
Disclosure includes VRT category mapping — useful for severity calibration

INTIGRITI:
Typically discloses within 90 days
Rich disclosure details (full PoC steps often included)
Disclosure is platform-wide visible

PRIVATE PROGRAMS:
Disclosure behavior varies by program rules
Some private programs disclose internally only
Cannot search Hacktivity for private program findings unless invited
```

---

## DEDUPLICATION AT SCALE

### Bulk Disclosure Analysis Workflow

At the start of an engagement:

```
1. PULL DISCLOSURE LIST:
   - Last 50 disclosures for target program
   - Export to CSV: title, date, severity, bug class, researcher

2. CATEGORIZE BY BUG CLASS:
   SQLi: __
   XSS: __
   IDOR: __
   SSRF: __
   CSRF: __
   Race: __
   Auth bypass: __
   Other: __

3. MAP BY ENDPOINT:
   /api/users: __ findings
   /api/admin: __ findings
   /checkout: __ findings

4. IDENTIFY COVERAGE GAPS:
   "Program has NO disclosed SSRF findings"
   "Program has NO disclosed GraphQL auth bypass findings"
   "Program's disclosed IDORs all cover GET requests"

5. FOCUS TESTING ON GAPS:
   Write these down as your testing priorities
   Revisit coverage gaps weekly as new disclosures appear
```

### Deduplication Decision Tree

```
Finding → Is there a disclosed report with same endpoint + class?

  NO → Is there a disclosed report with same endpoint, different class?
       YES → Different vuln on same asset → PROCEED (new bug)
       NO  → No disclosed coverage → PROCEED

  YES (same endpoint + class) → Read the full report:
        Same root cause? 
        YES → Does disclosed fix address your vector?
              YES → KILL (same bug, fixed)
              NO  → REGRESSION → Submit with regression note
        NO  → Different root cause → PROCEED
```

---

## HYBRID FINDINGS: PARTIAL DUPLICATION

### The "Partially Duplicate" Finding

Sometimes your finding overlaps with a disclosed one but isn't a complete duplicate:

```
PATTERN: Disclosed: IDOR on GET /api/users/{id} returns full user record
YOUR FINDING: GET /api/users/{id} returns full user record AND email change capability

SAME PORTION: The IDOR primitive (reading another user's data)
NEW PORTION: The ability to MODIFY another's data via same primitive

DECISION: 
- The IDOR read is duplicate (already disclosed)
- The IDOR write is NEW
- BUT: You can't really separate them in one report

OPTIONS:
A. Two reports: one for read, one for write (slightly redundant but valid)
B. One report: "IDOR on /api/users/{id} allows read and write" 
   (if read wasn't fully patched, this is a regression+expansion)

RECOMMEND: One report, clearly stating the write dimension is new,
referencing the disclosed read finding.
```

### The "Shared Root Cause" Finding

```
PATTERN: Disclosed: XSS in "name" field
YOUR FINDING: XSS in "name", "bio", "company", "location" fields

SAME ROOT CAUSE: Profile fields are not sanitized on save
DIFFERENT SURFACE: Multiple fields affected

DECISION:
- Some programs accept this as one "unsanitized profile fields" finding
- Others prefer one report per field
- Check prior disclosures: how did other researchers handle this?

SUBMISSION STRATEGY:
"XSS in user profile fields. The following fields accept and render
HTML without sanitization: name, bio, company, location. 
Reference: previous disclosure #XXXXX covered name specifically;
this report covers the full set of affected fields."

(One report, multiple fields, references disclosure for first field)
```

---

## RE-PENETRATION AFTER DEDUP DECISION

### When to Re-Test After a Disclosed Report

```
TIMELINE ANALYSIS:
[Disclosed Date] → [Fix Applied Date] → [Your Test Date]

Case 1: Fix never arrived
- Disclosed: "Fixed in v2.1"
- You test on v2.0 → vuln still present → NEW (this deployment wasn't fixed)

Case 2: Fix was partial
- Disclosed: "Added user ownership check"
- You test on v2.1 → GET has check but PUT doesn't → PARTIAL REGRESSION
- You report the PUT path specifically

Case 3: Fix was complete, then removed
- Disclosed: "Fixed in v2.1 on 2023-01-15"
- Changelog shows: "Reverted commit abc123 to fix regression in v2.2 on 2023-06-01"
- You test on v2.2 → fix gone → NEW (regression)

Case 4: Fix was complete but different asset
- Disclosed: "Fixed api.target.com"
- You test dev-api.target.com → vuln still present on dev tier
- Different asset → valid to report (inform dev team)
```

---

## DEDUPLICATION REPORTING BEST PRACTICES

### How to Handle Near-Duplicates in Report Notes

```
DEDUP NOTE TEMPLATE (for borderline cases):

---
## Deduplication Research Note

Closest disclosed report: [Researcher name], [Date], [Program Report #]

Comparison:
- Disclosure covers: GET /api/users/{id} → IDOR returning user PII
- This report covers: PUT /api/users/{id} → same IDOR pattern, write dimension
- Difference: HTTP method differs (GET vs PUT), data impact differs (read vs write)
- Root cause appears identical (missing ownership check on same function)

Decision rationale: 
POST/PUT/DELETE operations on /api/users/{id} use the same getUser()
call, which lacks authorization. The disclosed report covers GET only;
this report includes the write-side impact. Given that the program's
original fix for GET did not address PUT/DELETE, these represent
different attack surfaces enabled by the same root cause.

Requesting separate review. If program considers this the same root
cause, can be marked as a duplicate of #XXXX.
---

BE HONEST IN DEDUP NOTES:
- Don't spin a dup as "new" — triagers have seen everything
- Don't self-suppress a valid finding out of fear
- Acknowledge similarity, articulate difference, let triager decide
```

---

## DEDUPLICATION ANTI-PATTERNS

### Anti-pattern: Vapor Dedup

```
BAD: "I think this is a dup, so I'll just kill it"
GOOD: Read the actual disclosed report; make a real comparison

Cost of wrong dedup:
- You gave up a potential bounty
- The finding was actually unique and someone else might find it
- The program later fixes it without paying anyone (your loss)

Cost of wrong re-submission:
- N/A verdict
- Small reputation hit (usually recoverable)

BET: Submit with good dedup note. Let the triager decide.
```

### Anti-pattern: Dedup Different Bug Classes

```
BAD: "Disclosed IDOR exists on /api/users, so my XSS on same endpoint is a dup"
GOOD: IDOR and XSS are different bug classes on same endpoint → SEPARATE reports

Rule: Same endpoint ≠ same bug. Different classes are always separate.
```

### Anti-pattern: Scope Conflation in Dedup

```
BAD: "Disclosed report was on api.target.com, my finding is on cdn.target.com → dup!"
GOOD: Different subdomains are different assets → NEW reports

Rule: Determine scope first, then dedup. Out-of-scope findings don't dedup against in-scope.
```

---

## DEDUPLICATION SCOREBOARD

Track your deduplication accuracy:

```
MY DEDUP PERFORMANCE:

Month | Submissions | Passed dedup | Actual dups killed | False kills (wrongly killed valid) | Missed dups (submitted actual dup)
------|-------------|--------------|-------------------|-----------------------------------|--------------------------------
Jan   | 20          | 18           | 2                 | 0                                  | 1
Feb   | 25          | 22           | 3                 | 1                                  | 0
...

IDEAL: High "passed dedup" rate (your findings are unique)
       Low "false kills" (you didn't kill good findings)
       Low "missed dups" (program accepted all valid finds)

If false kills > 5%: Be less aggressive — submit with dedup note instead
If missed dups > 5%: Search harder before submitting
```

---

## FINAL DEDUPLICATION RULES

11. Search ALL sources — not just the first platform you find
12. Read disclosures in full — the details determine duplication
13. Map by endpoint, class, AND root cause — any dimension difference = new finding
14. Re-test disclosed bugs on current version — disclosed ≠ fixed
15. Look for method/parameter/role/chain angles — same primitive, new exploitation
16. Document your search and decision reasoning in the report
17. When uncertain: submit with dedup justification — let triager be the final judge
18. A clean dedup record is part of your researcher brand
