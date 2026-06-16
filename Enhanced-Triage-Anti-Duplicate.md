# Enhanced Triage & Anti-Duplicate Methodology

A comprehensive methodology for preventing duplicate bug bounty submissions and preparing evidence that survives triage. This document covers the full lifecycle — from pre-hunt research through post-submission monitoring — with platform-specific tactics, reusable checklists, and triage-defense templates.

## Table of Contents

1. [The Duplicate Problem](#the-duplicate-problem)
2. [Pre-Hunt Duplicate Prevention](#pre-hunt-duplicate-prevention)
3. [During-Hunt Duplicate Avoidance](#during-hunt-duplicate-avoidance)
4. [Pre-Submission Deep Search Protocol](#pre-submission-deep-search-protocol)
5. [Triage Readiness](#triage-readiness)
6. [Anti-Duplicate Evidence Strategies](#anti-duplicate-evidence-strategies)
7. [Triage Defense Kit](#triage-defense-kit)
8. [Platform-Specific Triage Tactics](#platform-specific-triage-tactics)
9. [Post-Submission Monitoring](#post-submission-monitoring)
10. [Building a Personal Anti-Duplicate Database](#building-a-personal-anti-duplicate-database)
11. [Case Studies](#case-studies)
12. [Anti-Duplicate Checklist](#anti-duplicate-checklist)

---

## The Duplicate Problem

### Why Duplicates Are the #1 Reason for N/A on Mature Programs

On mature bug bounty programs — those that have been running for 12+ months — duplicates account for 40-60% of all N/A (Not Applicable) determinations. This isn't because researchers keep finding the same bugs. It's because:

| Factor | Impact |
|--------|--------|
| Program maturity | Older programs have larger internal duplicate DBs |
| Researcher volume | More hunters = more overlap in findings |
| Shallow testing | Surface-level bugs are found by everyone |
| Poor prior-art search | Most hunters skip pre-hunt research entirely |
| Narrow root-cause analysis | Same bug, different endpoint — called "new" |

The programs with the highest bounties (Google, Facebook, Microsoft, Apple) also have the most mature triage processes and the largest internal databases of known issues. A finding that would pay $5,000 on a new program gets marked N/A on a mature program because three other people already reported it.

### Financial Impact of Duplicates

| Cost Type | Calculation |
|-----------|-------------|
| Wasted time | 4-8 hours hunting + 1-2 hours reporting = 6-10 hours per duplicate |
| Reputation damage | Each N/A submission hurts your signal-to-noise ratio |
| Program suspension risk | >30% N/A rate may trigger platform review/suspension |
| Opportunity cost | Time on a duplicate = time NOT spent on a novel finding |
| Earning potential | A top-tier researcher who avoids duplicates earns 3-5x more |

A researcher who submits 100 reports per year with a 30% duplicate rate wastes 180-300 hours on unfindable work. That's 4-7 work weeks.

### Duplicate Rates by Platform

| Platform | Estimated Duplicate Rate | Notes |
|----------|-------------------------|-------|
| HackerOne | 35-50% | Largest disclosed report DB helps, but also largest researcher base |
| Bugcrowd | 30-45% | VRT-based triage; fewer disclosed reports = less visibility |
| Intigriti | 25-40% | Smaller researcher pool, but programs tend to be newer |
| Immunefi | 20-35% | Smart contract bugs are more unique, but duplicates still happen |

The disclosed report DB size significantly impacts duplicate prevention ability. HackerOne's massive public archive is both a blessing (you can search it) and a curse (everyone else can too).

### Near-Duplicate vs Exact Duplicate

| Type | Definition | Triager Treatment |
|------|------------|-------------------|
| **Exact duplicate** | Same endpoint, same parameter, same root cause, same impact | Immediate N/A, merged into original |
| **Near-duplicate** | Different endpoint/parameter but same root cause/class | N/A if internal team considers it equivalent; may be filed as variant |
| **Known limitation** | Documented by the program as accepted risk | N/A with reference to documentation |
| **Variant** | Same underlying bug class, different attack path or trigger | Case-by-case — must be differentiated in submission |

The most frustrating N/A is the near-duplicate. The program triager decides your novel attack path is "essentially the same" as an existing report. Section 6 of this document shows how to preempt that determination.

### How Triagers Use Internal Duplicate DBs

Triagers do not manually remember every report. They use internal systems:

1. **Keyword search** — Triager searches for "SQL injection" + "export" and finds 5 related reports
2. **Parameter matching** — Triager checks if the reported parameter matches a known vulnerable parameter
3. **Endpoint grouping** — Triager groups reports by endpoint to identify duplicates
4. **Root-cause clustering** — Triager tags by root cause (e.g., "missing ownership check in service layer") and groups similar findings
5. **Impact comparison** — Triager assesses whether the demonstrated impact is already covered by an existing fix

**Key insight:** Triagers classify by root cause, not by endpoint. If you report an IDOR on `/api/v2/users/{id}/profile` but a previous report covered `/api/v1/users/{id}`, the triager sees both as "missing user_id check in user profile endpoint" and marks yours as duplicate.

Your job is to prove your finding has a *different root cause* or a *significantly different impact*.

---

## Pre-Hunt Duplicate Prevention

### Prior Art Research Before Writing a Single Request

The most effective time to prevent duplicates is *before you start hunting*. Every hour spent on prior-art research saves 4-6 hours of hunting a dead end.

#### HackerOne Disclosed Reports

```
site:hackerone.com/reports "target.com" "IDOR"
site:hackerone.com/reports "target.com" "privilege escalation"
site:hackerone.com/reports "target.com" "information disclosure"
```

Search by:
- Domain: `site:hackerone.com/reports target.com`
- Program name: `site:hackerone.com/reports "Target Program Name"`
- Vulnerability class: `site:hackerone.com/reports target.com IDOR`
- Year: `site:hackerone.com/reports target.com 2025`

**Pro tip:** Use `-site:hackerone.com/reports "target" "disclosed"` to find reports that mention the same target on external sites.

#### Bugcrowd Disclosed Reports

```
site:forum.bugcrowd.com "target.com" "submission"
site:forum.bugcrowd.com target.com
site:forum.bugcrowd.com target
```

Bugcrowd's disclosure is less comprehensive than HackerOne's, but the forum often contains discussions of resolved submissions.

#### Intigriti Disclosed Reports

Intigriti occasionally publishes writeups. Search:

```
site:intigriti.com "target.com" bug
site:medium.com intigriti target.com
```

#### GitHub Issue Tracker Search

Many targets have open-source components. Search their GitHub repos:

```
org:target-org "security" "vulnerability" is:issue
org:target-org "security" is:closed is:issue
org:target-org "CVE-" is:issue
```

Also search for security-relevant keywords in private repos that might have public issues:

```
"target-org" "security.txt" "vulnerability disclosure"
"target-org" "hall of fame" "acknowledgements"
```

#### CVE Database Search for the Target Tech Stack

```
site:nvd.nist.gov "product" "version" target-component
site:github.com "CVE" target-component
site:exploit-db.com target-component
```

If the target runs Apache 2.4.49, search for CVEs. If you find CVE-2021-41773 (path traversal), check if the target's custom code on top of Apache has similar vulnerabilities.

#### Google Dorks for Vulnerability Disclosure

```
"target.com" "vulnerability disclosure" "thank you"
"target.com" "responsible disclosure" "report"
"target.com" "security advisory"
"target.com" "bug bounty" "rewarded"
"target.com" "hall of fame" OR "acknowledgements"
"target.com" "security.txt"
"target.com" "thanks to" researcher
```

#### Wayback Machine for Previous Researcher Reports

```
web.archive.org/web/*/target.com/security.txt
web.archive.org/web/*/target.com/.well-known/security.txt
web.archive.org/web/*/target.com/hackerone-report-*
```

Previous versions of the target's security page, policy page, or disclosed report mirrors may reveal what's been found.

#### Twitter and Telegram Bug Bounty Community Chatter

```
site:twitter.com target.com "bug bounty"
site:twitter.com target.com "disclosed"
site:telegram.me target.com bug
```

Also check bug bounty discords (Infosec, Bug Bounty World, etc.) for discussions about the target.

### Tool: prior_art.sh — Automate Searches Across All Sources

```bash
#!/bin/bash
# prior_art.sh — Automated duplicate research across platforms
# Usage: ./prior_art.sh target.com

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 target.com"
    exit 1
fi

echo "=== Searching HackerOne disclosed reports ==="
curl -s "https://hackerone.com/rewrites/reports?query=$TARGET&sort=latest_disclosable_activity_at&order=desc" | \
    jq '.results[].title' 2>/dev/null || echo "No results or API changed"

echo "=== Searching GitHub issues ==="
gh search issues --repo "target-org/$TARGET" --label security --json title,url 2>/dev/null || \
    echo "No GitHub results for $TARGET"

echo "=== Searching CVE database ==="
curl -s "https://cve.circl.lu/api/search/$TARGET" | jq '.cves[] | {id, summary}' 2>/dev/null || \
    echo "No CVEs found"

echo "=== Searching security.txt acknowledgements ==="
curl -s "https://$TARGET/.well-known/security.txt" | grep -i "hackerone\|bugcrowd\|intigriti" || \
    echo "No security.txt found"

echo "=== Checking Wayback Machine for historical reports ==="
curl -s "http://web.archive.org/cdx/search/cdx?url=$TARGET/security*&output=json" | \
    jq '.[1:][] | .[2]' 2>/dev/null | head -20 || echo "No Wayback results"

echo "=== Done ==="
```

Save this as `prior_art.sh` and run it on any new target. Add additional sources as you discover them.

### Building a Target-Specific Known-Vulnerability Database

Before starting, create a structured document:

```yaml
target: target.com
program: Target Program (H1)
last_updated: 2026-06-16

known_bugs:
  - class: IDOR
    endpoint: /api/v1/users/{id}/profile
    severity: High
    date_found: 2025-03-01
    status: Fixed
    report: h1://123456
    variant_check: Check /api/v2/users/{id}/profile for regression

  - class: XSS
    endpoint: /search?q=
    severity: Medium
    date_found: 2025-06-15
    status: Fixed
    report: h1://123789
    variant_check: Check /api/search?q= for stored XSS

  - class: Race Condition
    endpoint: POST /api/checkout
    severity: Critical
    date_found: 2025-09-01
    status: Fixed
    variant_check: Check POST /api/cart/checkout in new version

attack_surface_remaining:
  - GraphQL introspection still enabled
  - No rate limiting on password reset
  - subdomain.target.com uses older framework version
```

Track this file in a private repo. Update it after every disclosed report you read.

### Tracking What's Been Found vs What's Likely Remaining

Use the vulnerability class distribution to predict remaining surface:

| Bug Class | Typical Program Lifecycle | Likelihood Remaining |
|-----------|--------------------------|---------------------|
| Reflected XSS | Found in first 3 months | Low — automated scanners catch these |
| Stored XSS | Found in first 6 months | Medium — depends on input surface |
| SQLi | Found in first 3 months | Very low — WAF + ORM prevent most |
| IDOR | Ongoing — never fully solved | High — new features introduce new IDORs |
| Business Logic | Ongoing — never fully solved | High — requires human creativity |
| Race Condition | Found sporadically | Medium — hard to find, but also hard to exploit |
| SSRF | Found in first 12 months | Medium — depends on feature surface |
| Auth Bypass | Ongoing — never fully solved | High — new auth flows introduce new bypasses |
| GraphQL | Found in first 6 months | Medium — depends on query surface |
| Cache Poison | Found rarely | High — often overlooked by automated testing |

IDOR, business logic, and auth bypass are the classes with the most "remaining" surface on mature programs because they require application-specific understanding and creative testing.

---

## During-Hunt Duplicate Avoidance

### Avoiding the Obvious Paths Everyone Checks First

Every program has "obvious" endpoints that every researcher hits first. These are the most likely to be duplicate territory:

| Obvious Path | Why Everyone Hits It | Duplicate Rate |
|--------------|---------------------|----------------|
| `/api/user/profile` | IDOR testing 101 | ~70% |
| `/api/orders/{id}` | E-commerce IDOR | ~65% |
| `/search?q=` | XSS testing | ~80% |
| `/graphql` | Introspection | ~60% |
| `/api/admin/users` | Privilege escalation | ~75% |
| `/api/upload` | File upload testing | ~70% |
| Password reset flow | Account takeover | ~65% |

**Strategy:** Skip these entirely in the first pass. Focus on:

1. **New features** — Recently launched endpoints have fewer researcher eyes
2. **Beta features** — Often have less security review
3. **Internal/admin endpoints** — Found via JS analysis, not directory busting
4. **Edge-case parameters** — Not the `id` but the `include_deleted`, `export_format`, `callback_url`
5. **Third-party integrations** — Webhooks, OAuth flows, SSO configs — often overlooked

### Same Bug, Different Endpoint: How to Check If Your Finding Is Truly Novel

When you find a bug, ask these questions before writing a report:

| Question | If Yes | If No |
|----------|--------|-------|
| Is this the same endpoint as a known bug? | High chance of duplicate | Good sign — likely novel |
| Is this the same parameter as a known bug? | Check if root cause differs | Good sign |
| Is this the same root cause as a known bug? | Near-duplicate risk | Likely novel |
| Is this the same impact as a known bug? | Triager may merge | Good sign |
| Can I chain this for higher impact? | Novel contribution possible | Standalone finding may be weak |

**Example:**

```
Known bug: IDOR on GET /api/v1/orders/{id} (missing owner_id check)
Your find:  IDOR on POST /api/v1/orders/{id}/cancel (missing owner_id check)
```

- Same root cause (missing owner_id check)
- Same endpoint family (/api/v1/orders/)
- Different impact (state change vs data read)
- **Result:** Near-duplicate. Triager will likely mark as duplicate because the root cause fix for the known bug should have covered this too. Unless you can prove the fix was incomplete and this endpoint was missed.

**Better find:**

```
Known bug: IDOR on GET /api/v1/orders/{id}
Your find:  IDOR on GET /api/v2/warehouse/inventory/{id}
```

- Different root cause (inventory service vs order service)
- Different endpoint family
- Different impact (warehouse data vs order data)
- **Result:** Likely novel. But still check disclosed reports for warehouse/inventory endpoints.

### Surface-Level vs Deep Variants

Understanding the distinction between surface-level and deep variants is critical to avoiding near-duplicate N/As.

#### Same Parameter, Different Endpoint — Likely Duplicate

```
Known:  GET /api/v1/orders/{id}?include_details=true  → IDOR
Your:   GET /api/v1/invoices/{id}?include_details=true  → IDOR
```

If both endpoints share the same code path (e.g., a generic `getResource` function), this is a duplicate of the underlying issue. The triager will mark it as such.

#### Same Root Cause, Different Attack Path — Possibly Novel

```
Known:  IDOR via direct numeric ID enumeration
Your:   IDOR via GraphQL batch query that bypasses the ORM filter
```

The root cause is the same — missing authorization check. But the attack path is entirely different. If the program's fix only addressed the REST endpoint, the GraphQL vector may be a separate bug. **You must explicitly state this in your report.**

#### Same Impact, Different Tech Stack — Probably Duplicate

```
Known:  Reflected XSS in search endpoint on target.com
Your:   Reflected XSS in search endpoint on subdomain.target.com
```

If both applications are owned by the same company and use the same codebase, this is a duplicate. The fix for one should propagate to the other. Unless you can prove the subdomain runs different code, skip it.

#### Same Class, Different Trigger — Check Disclosed Reports

```
Known:  CSRF on email change endpoint (no token validation)
Your:   CSRF on phone number change endpoint (no token validation)
```

CSRF is typically fixed centrally (add token validation middleware). If the program added CSRF tokens to email change, they likely added them to all sensitive endpoints. Check before reporting.

### The "We're Already Aware Of This" Deflection

When a triager says "we're already aware of this," they mean one of:

1. **Internal finding** — Their security team already found it
2. **Previous report** — Another researcher reported it (may be fixed or pending)
3. **Known limitation** — They've accepted the risk
4. **Near-duplicate** — Your finding is close enough to an existing report

**How to prove your variant is different:**

```
Template: Differentiation Statement

"While I understand report #12345 covers missing authorization on 
GET /api/v1/orders/{id}, my finding is distinct because:

1. Attack vector: My finding uses POST /api/v1/orders/{id}/cancel which
   is a mutative endpoint, not a read endpoint. The impact includes
   unauthorized cancellation of orders, not just data access.

2. Authorization layer: The GET endpoint may be protected by the
   read-order scope, while the POST endpoint may have an entirely
   separate authorization check that was overlooked.

3. Business impact: Unauthorized order cancellation causes financial
   loss and customer dissatisfaction, which is a different damage
   profile from data exposure.

4. Fix scope: A fix for the GET endpoint (adding owner_id check to
   the read query) does not automatically fix the POST endpoint
   (which may need ownership validation in the cancel-order service).

I recommend treating this as a separate finding or at minimum
verifying that the planned fix covers both vectors."
```

### Tracking Your Own Testing to Avoid Resubmitting Your Own Previous Findings

Keep a local log of everything you test:

```json
{
  "session_id": "2026-06-16-target-com",
  "target": "target.com",
  "hunter": "me",
  "tests": [
    {
      "endpoint": "GET /api/v1/users/{id}",
      "tested": ["{id} = 1-100, {id} = uuid-*"],
      "found": true,
      "bug_class": "IDOR",
      "status": "submitted",
      "report_id": "h1://789012",
      "result": "paid"
    },
    {
      "endpoint": "POST /api/v1/users/{id}/avatar",
      "tested": ["SVG upload", "PHP webshell", "...png"],
      "found": false,
      "bug_class": null,
      "status": "clean"
    },
    {
      "endpoint": "POST /api/auth/reset-password",
      "tested": ["host header injection", "token prediction"],
      "found": true,
      "bug_class": "ATO",
      "status": "submitted",
      "report_id": "h1://789013",
      "result": "N/A (duplicate)"
    }
  ]
}
```

Use this log to:
- Avoid retesting endpoints you already covered
- Identify patterns in what you find (are you good at IDOR? SSRF?)
- Track what paid vs N/A'd to improve targeting

---

## Pre-Submission Deep Search Protocol

### The 15-Minute Mandatory Search Before Any Submission

Before writing a single word of any report, spend 15 minutes on this protocol. Set a timer. Do not skip steps.

#### Step 1: Search H1/Bugcrowd Disclosed for Target + Vuln Class (2 min)

```
site:hackerone.com/reports target.com "IDOR"
site:hackerone.com/reports target.com "authorization"
site:hackerone.com/reports target.com/orders
```

For Bugcrowd:
```
site:forum.bugcrowd.com target.com authorization
```

Scan the titles and dates. If you see reports that match your finding's general class, read the full disclosure to confirm differentiation.

#### Step 2: Search GitHub Issues for Security Labels (2 min)

```
org:target-org is:issue label:security
org:target-org is:issue "vulnerability"
org:target-org is:issue "security advisory"
org:target-org is:issue "CVE"
```

Also search the target's public repos for any security-related issues or pull requests. Sometimes fixes are discussed publicly before the report is disclosed.

#### Step 3: Search CVE/NVD for Component + Vuln Type (2 min)

```bash
# Quick CVE check
curl -s "https://cve.circl.lu/api/search/$(echo $TARGET | cut -d. -f1)" | \
    jq '.cves[] | select(.summary | test("IDOR|auth|authorization"; "i")) | {id, summary}'
```

If the target uses a known vulnerable component version, check if your finding is a known CVE or a variant of one.

#### Step 4: Search Change Logs / Release Notes for "Security" (1 min)

```
site:target.com changelog security
site:target.com release notes fix
site:target.com/security
```

If the target has a public changelog that mentions "fixed an authorization issue," your finding may be a regression or variant of the fix.

#### Step 5: Search Community Discord/Slack Archives (1 min)

If you're in bug bounty communities, search:
- Discord: `target.com` in #disclosures or #finding-discussion
- Telegram: search target name in bug bounty group archives
- Slack workspaces for researchers

#### Step 6: Search Twitter for Target + Bug Bounty Mentions (1 min)

```
from:researcher target.com "bug bounty"
target.com "disclosed" "report"
target.com "bounty" "awarded"
```

#### Step 7: Check If Same Pattern Was Reported for Similar Tech Stack (1 min)

If the target uses Django REST Framework, search for Django IDOR disclosures on other programs. If the pattern matches (missing `get_queryset` override), the same root cause likely applies here.

#### Step 8: Google Dork the Exact Payload You Plan to Use (1 min)

```
"GET /api/v1/users/" "order by" "id"
"privilege escalation" "target" "example payload"
```

If your exact payload appears in a disclosed report or writeup, your finding is highly likely to be a duplicate.

#### Step 9: Check If the Finding Is in a "Known Limitations" Doc (1 min)

```
site:target.com "known limitations" "known issues"
site:target.com/docs "not implemented" "security"
site:target.com/status
```

Some programs document accepted risks. Check before you report.

#### Step 10: Search If the Component Has a security.txt with Acknowledgements (1 min)

```
curl -s https://target.com/.well-known/security.txt | grep -i "hackerone\|acknowledgements\|hall of fame"
curl -s https://target.com/security.txt | grep -i "hackerone\|acknowledgements\|hall of fame"
```

If the target publicly acknowledges researchers, check the list of previously reported findings.

### Document the Search Results in Your Report Appendix

```markdown
## Prior Art Search Results

As part of my pre-submission protocol, I conducted the following searches:

| Source | Query | Results |
|--------|-------|---------|
| H1 Disclosed | site:hackerone.com/reports target.com "IDOR" | No matching reports |
| H1 Disclosed | site:hackerone.com/reports target.com/orders | 1 related report (#12345 — different endpoint) |
| GitHub Issues | org:target-org is:issue security | 3 closed issues, none related |
| CVE Database | target-component 2.x | No relevant CVEs |
| Change Log | site:target.com/changelog "security" | No matching entries |
| Google Dork | exact payload string | 0 results |
| security.txt | /well-known/security.txt | 5 researchers acknowledged, none for this class |

**Conclusion:** After thorough search, I believe this finding is novel and not previously reported.
```

This appendix serves two purposes:
1. It shows the triager you did your homework
2. It makes it harder for the triager to claim "this is a known issue" without evidence

If the triager responds with a duplicate reference, you can point to your search protocol as evidence that the finding was not discoverable through public channels.

---

## Triage Readiness

### Why Reports Get Marked N/A Even When Valid

A finding can be 100% valid and still get N/A. The most common reasons:

| Reason | Frequency | Prevention |
|--------|-----------|------------|
| Insufficient reproduction steps | 35% | Write step-by-step from fresh state |
| Missing environment details | 20% | Include app version, browser, OS |
| Unclear business impact | 15% | Write impact statement first |
| Triager couldn't reproduce | 15% | Record video PoC, include curl commands |
| Scope ambiguity | 10% | Cite scope policy in report |
| Duplicate (undisclosed) | 5% | Deep prior-art search |

Every report should pass the "fresh state test": can a triager with no prior knowledge of the finding reproduce it from scratch in under 5 minutes?

### Evidence Package Requirements

#### Request/Response Pairs — Formatted, Not Raw

```http
# Bad: Raw copy-paste
GET /api/users/123 HTTP/1.1
Host: target.com
Authorization: Bearer eyJ...

# Good: Annotated with explanation
=== REQUEST ===
GET /api/users/123 HTTP/1.1
Host: target.com
Authorization: Bearer <token for User A (low-privilege)>

=== RESPONSE ===
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 123,
  "email": "admin@target.com",
  "role": "admin",
  "internal_notes": "VIP customer"
}

=== NOTE ===
User A (low-privilege) successfully retrieved the profile of user 123
(admin). The endpoint does not verify that the requesting user owns the
target user ID.
```

#### Step-by-Step Reproduction — Must Work from Fresh State

```
## Reproduction Steps

### Prerequisites
- Two accounts: User A (low-privilege, test@example.com) and User B 
  (admin, admin@example.com)
- Both accounts must have completed onboarding
- Browser: Chrome 120+ or any modern browser

### Steps
1. Log in as User A (test@example.com / password123)
2. Open Chrome DevTools → Network tab
3. In the console, execute:
   ```javascript
   fetch('/api/users/123', {
     headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
   }).then(r => r.json()).then(console.log)
   ```
4. Observe that the response contains User B's admin profile data
5. Repeat step 3 with any user ID (1-1000) to enumerate all users

### Expected vs Actual
- Expected: Only User A's own profile should be returned
- Actual: Any user's profile is returned for any user ID
```

#### Two Accounts Minimum for Multi-Tenant Bugs

For any bug involving user data access:
- **Account A:** Creates the resource (document, order, profile, etc.)
- **Account B:** Attempts to access the resource

Both accounts must be demonstrated in the PoC. Screenshots should show both browser windows/sessions.

#### Video PoC Guidelines

| Requirement | Standard |
|-------------|----------|
| Max duration | 60 seconds |
| Resolution | 1920x1080 |
| Format | MP4 (H.264) |
| Annotation | Text boxes showing step numbers |
| Audio | Not required, but helpful for narration |
| File size | Keep under 50MB (compress if needed) |
| Tool | OBS, Loom, or screen recording built into macOS/Windows |

Video content structure:
1. 0-5s: Show both accounts logged in
2. 5-30s: Account A creates resource
3. 30-50s: Account B accesses resource (show the violation)
4. 50-60s: Show the impact (sensitive data, admin panel, etc.)

#### HAR File Sanitization

Before attaching a HAR file, sanitize it:

```bash
# Remove cookies from HAR file
jq 'del(.log.entries[].request.cookies)' input.har > output.har

# Remove Set-Cookie headers
jq 'del(.log.entries[].response.headers[] | select(.name == "Set-Cookie"))' \
    output.har > sanitized.har

# Remove Authorization headers
jq 'del(.log.entries[].request.headers[] | select(.name == "Authorization"))' \
    sanitized.har > final.har

# Verify no sensitive data remains
cat final.har | grep -i "cookie\|authorization\|bearer\|session" || echo "Clean"
```

#### Screenshot Discipline

| Element | Action |
|---------|--------|
| Session cookies | Redact with black bar or blur |
| Other user PII | Names, emails, phone numbers → redact |
| IP addresses | Internal IPs only if relevant; mask public IPs |
| Request body | Show only relevant fields |
| Response body | Show only the data proving the violation |
| Browser URL bar | Include — shows full URL with parameters |
| DevTools Network tab | Include — shows request/response headers |

#### Clear Before/After Comparison

Every report needs a control demonstration:

```
=== BEFORE (Normal Operation) ===
User A accesses User A's resource → Success (expected)

=== AFTER (Exploit) ===
User A accesses User B's resource → Success (vulnerability)
```

Or for information disclosure:

```
=== BEFORE (Expected) ===
GET /api/users/me → { "email": "user@example.com" }

=== AFTER (Vulnerability) ===
GET /api/users/999 → { "email": "admin@target.com", "role": "admin" }
```

### The Triage Readiness Checklist

| Item | Check |
|------|-------|
| Step-by-step reproduction from fresh state | ☐ |
| Two accounts demonstrated (if applicable) | ☐ |
| Request/response pairs annotated | ☐ |
| Video PoC < 60 seconds, annotated | ☐ |
| HAR file sanitized (no cookies/auth) | ☐ |
| Screenshots with PII redacted | ☐ |
| Before/after comparison shown | ☐ |
| curl commands for each step | ☐ |
| Impact statement written | ☐ |
| Scope citation (which part of policy) | ☐ |

---

## Anti-Duplicate Evidence Strategies

### How to Prove Your Finding Is Distinct from Known Issues

#### Root Cause Analysis That Differs from Existing Reports

If a known bug has root cause A, and your bug has root cause B, document the difference:

```markdown
### Root Cause Differentiation

**Known report #12345:** Missing authorization check in the API Gateway
layer. The JWT validation middleware did not check the user_id claim
against the requested resource. This was fixed by adding a middleware
check.

**My finding:** Missing authorization check in the *service layer*. The
API Gateway correctly validates the JWT and passes user context to the
service, but the service method `getOrder(id)` queries the database
without adding `AND owner_id = $current_user`. This is a defense-in-depth
bypass that persists even after the gateway fix.

**Why this matters:** The known fix only addressed the gateway layer.
The service layer still trusts the client-provided order ID without
validating ownership. This means any client that can call the service
directly (internal services, admin panels, future API versions) can
still exploit this.
```

#### Impact Demonstration That Goes Beyond Known Surface

If the known bug had limited impact but yours has wider impact:

```markdown
### Impact Differentiation

**Known issue:** IDOR on GET /api/orders/{id} — revealed order metadata
(order date, status, total). Limited to read access on non-sensitive
fields.

**My finding:** IDOR on GET /api/orders/{id}/invoice — reveals full
invoicing data including billing address, tax ID, payment method
(last 4 digits), and customer notes. Additionally, the same endpoint
allows downloading the invoice PDF which contains the full billing
address and phone number.

**Impact comparison:**
- Known: PII exposure (name, email, order total) — Medium severity
- My finding: PII exposure (full address, phone, tax ID, payment info) 
  + document download — High severity

**CVSS difference:** Known: 5.3 (Medium). Mine: 7.5 (High) due to
expanded scope of exposed data and additional attack vector (PDF
download).
```

#### Chain Potential That Wasn't Previously Documented

Even if the standalone bug is similar to a known issue, if you can chain it for higher impact, the chain is novel:

```markdown
### Chain Potential

The known IDOR (report #12345) was reported as a standalone finding
with limited impact (read order metadata).

My finding extends this to a **3-step attack chain:**

1. IDOR on GET /api/orders/{id}/cancel-reason — reveals the
   cancellation reason field (known bug surface)

2. **New:** The cancel-reason endpoint accepts a PUT request that
   updates the cancellation reason. This allows an attacker to
   inject arbitrary text into another user's order record.

3. **New:** The cancellation reason is rendered in the customer
   support dashboard template WITHOUT sanitization, enabling
   stored XSS against support agents.

Total chain: IDOR → Data Tampering → Stored XSS → Admin Session Hijack

Impact escalation: Low (data read) → Critical (admin session takeover)
```

#### New Attack Surface the Program May Not Have Considered

```markdown
### Previously Unconsidered Attack Surface

The program's security review focused on REST API endpoints 
(/api/v1/*). My finding targets the recently launched GraphQL 
endpoint (/graphql) and WebSocket interface (/ws/live-orders), 
which were not covered by prior security assessments.

| Surface | Prior Coverage | Status |
|---------|---------------|--------|
| REST /api/v1/orders/* | Reviewed (report #12345) | Fixed |
| REST /api/v2/orders/* | Reviewed (report #12345 scope) | Same bug, different version |
| GraphQL mutation cancelOrder | Not reviewed | Vulnerable |
| WebSocket /ws/orders | Not reviewed | Vulnerable |

The missing authorization check propagates to all interfaces because
it's in the shared service layer, but the program only fixed the REST
v1 endpoint.
```

#### Regression in a Previously Fixed Feature

If a bug was fixed but the fix was incomplete:

```markdown
### Regression Analysis

The original IDOR (report #12345) was fixed by adding an owner_id check
to `OrdersController.show()`. However, the fix only covered the primary
`show` action.

The same controller has these additional actions:

```ruby
# Fixed
def show
  @order = Order.where(id: params[:id], owner_id: current_user.id).first
end

# NOT fixed — my finding
def cancel
  @order = Order.find(params[:id])  # No owner_id check!
  @order.cancel!
end

# NOT fixed — my finding
def duplicate
  @order = Order.find(params[:id])  # No owner_id check!
  @new_order = @order.dup
  @new_order.save!
end
```

The fix was incomplete because it only covered one code path. Three
other actions in the same controller have the same vulnerability.
```

### When to Explicitly Acknowledge Related But Different Findings

Honesty is the best policy. If you know a related finding exists, say so — and explain the difference:

```markdown
### Relationship to Report #12345

I am aware of report #12345 which covers missing authorization on 
GET /api/orders/{id}. My finding is related but distinct:

| Aspect | Report #12345 | My Finding |
|--------|---------------|------------|
| Endpoint | GET (read) | POST (write) |
| Impact | Data exposure | State manipulation |
| Root cause | Missing read auth | Missing write auth |
| Fix required | Add check to read method | Add check to write method |

Both findings share the same root vulnerability class (missing
authorization), but the fix for one does not address the other. I
recommend treating these as related but separate findings, or
expanding the scope of the existing fix to cover all HTTP methods.
```

This approach:
- Shows the triager you're not trying to hide the relationship
- Provides clear differentiation criteria
- Makes it easy for the triager to escalate to "related finding" instead of "duplicate"

### CVSS Calculation Framing That Highlights Unique Impact

Calculate CVSS for *your* finding, not for the class:

```markdown
### CVSS 3.1 Calculation

| Metric | Value | Reason |
|--------|-------|--------|
| AV:N/AC:L | Network, Low | No special access required |
| PR:L | Low | Requires authenticated session |
| UI:N | None | No user interaction |
| S:C | Changed | Affects resources of other users |
| C:H | High | Full read access to other users' data |
| I:L | Low | Can modify other users' data |
| A:N | None | No availability impact |

Base Score: 8.1 (High)

**Why this is not the same CVSS as report #12345:**
- Report #12345 had I:N (no integrity impact) → score 6.5
- My finding has I:L because the PUT endpoint allows modification
- This is a meaningful difference in severity justification
```

---

## Triage Defense Kit

### Anticipated Triager Questions and Pre-Prepared Answers

#### "This Is Out of Scope"

**Triager:** "The endpoint you tested is marked as out of scope in our policy."

**Rebuttal template:**

```
The program scope policy states:

> "The following are out of scope: [xyz]"

My finding targets [specific endpoint/resource], which does not
appear in the out-of-scope list. Specifically:

- The policy lists [A, B, C] as out of scope
- My finding targets [D], which is not in that list
- [D] falls under the in-scope category of "all other 
  subdomains/endpoints owned by the program"

If the program considers [D] to be out of scope, I request
clarification on which part of the scope policy applies.
```

**If rate limiting is claimed as the issue:**

```
The program's VRT lists "rate limiting" as informational. However,
my finding is not about the presence of rate limiting — it is about
[describe actual bug, e.g., "missing authorization on a write
endpoint"]. The rate limiting is an additional control, not a
replacement for authorization. Per OWASP, rate limiting is a
defense-in-depth measure, not a substitute for access controls.
```

#### "Rate Limiting Is Acceptable"

**Triager:** "Rate limiting on this endpoint is an acceptable mitigation."

**Counter:**

```
Rate limiting does not provide security — it provides delay. An
attacker with a distributed botnet (or simply patient enough to
respect the rate limit) can still exploit the underlying
vulnerability. The finding is not "rate limiting is missing" but
rather "[vulnerability class] exists." Rate limiting is a separate
control and does not address the root cause.

Additionally, the rate limit currently in place [number] requests per
[timeframe] does not prevent enumeration. At this rate, an attacker
could enumerate all [number] user IDs in [timeframe].
```

#### "This Requires Authenticated Access"

**Triager:** "The attacker needs to be authenticated, so this is a low-severity finding."

**Counter:**

```
Authentication proves identity. It does not prove authorization.
My finding demonstrates horizontal privilege escalation: User A
(authenticated) can access User B's data. This is a well-recognized
security boundary violation per OWASP and the program's own VRT.

The threat model is:
1. User A has legitimate access to the application
2. User A should NOT have access to User B's data
3. The application fails to enforce this boundary

This is distinct from "requires authenticated access" which would
imply the attacker needs privileged credentials. Any legitimate user
of the application can exploit this.
```

#### "This Is a Duplicate of #12345"

**Triager:** "We've already received a report for this issue."

**Differentiation response:**

```
Thank you for the reference. I've reviewed report #12345 and believe
my finding is distinct for the following reasons:

1. [List specific differentiation points]
2. [Reference the table from Section 6]
3. [Propose how to verify the difference]

If the triage team determines this is indeed a duplicate, I request
that the finding be noted as a variant of #12345, as it demonstrates
incomplete fix coverage.
```

#### "This Is a Known Limitation"

**Triager:** "This is a known limitation that we've accepted as a business decision."

**Counter:**

```
I understand the program may have documented this as a known
limitation. However, I believe this finding warrants re-evaluation
because:

1. [Why the limitation is no longer acceptable — e.g., new regulation,
   new data type exposed, user growth increases risk]
2. [Why the security impact exceeds the business justification]
3. [Suggested compromise — e.g., partial fix, additional monitoring]

If the program maintains its position, I request a link to the
public documentation of this known limitation for my records.
```

#### "Can't Reproduce"

**Triager:** "I followed your steps but couldn't reproduce the issue."

**Response:**

```
I apologize for the unclear instructions. Let me provide more detail:

1. Environment: [Exact details — browser version, OS, network]
2. Account state: [What the account needs — confirmed email, 
   specific subscription tier, specific feature enabled]
3. Timing: [If time-sensitive — e.g., "must be within 5 minutes of
   account creation"]
4. Alternative method: [Provide curl commands or a fresh video PoC]

If the issue still cannot be reproduced, I am available for a live
demonstration or to provide additional debugging information.
```

### Severity Downgrade Counters

#### "Informational" — Why It's At Least Low

| Criteria | Your Argument |
|----------|---------------|
| User enumeration | "Knowing a user exists is the first step in a targeted attack. Combined with password reset or credential stuffing, this enables account takeover." |
| Missing security header | "Missing HSTS/CSP/X-Frame-Options enables phishing/XSS/clickjacking attacks against users." |
| Verbose error message | "Error messages that distinguish between 'user exists' and 'wrong password' enable user enumeration at scale." |

#### "Low" — Why It's At Least Medium

| Criteria | Your Argument |
|----------|---------------|
| Reflected XSS with login required | "Post-authentication XSS allows session hijacking and privilege escalation. It is not self-XSS if the attacker can force the victim to visit the crafted URL." |
| IDOR on non-sensitive field | "Exposure of any user-specific information is a privacy violation under GDPR/CCPA. Additionally, composite data from multiple endpoints can enable account enumeration." |
| Missing rate limit | "Rate limit absence on sensitive endpoints (login, password reset, MFA) enables brute force. On write endpoints, it enables data destruction at scale." |

#### "Medium" — Why It's At Least High

| Criteria | Your Argument |
|----------|---------------|
| Stored XSS | "Stored XSS affects all users who view the page, persists across sessions, and can be used for mass session hijacking. Per the VRT, this is at minimum High." |
| IDOR on sensitive data | "Exposure of PII (email, phone, address) constitutes a data breach. Under GDPR, a breach must be reported to regulators within 72 hours. This is High/Critical." |
| CSRF on state-changing action | "CSRF on email change, password change, or financial operations enables account takeover without user interaction." |

#### "High" — Why It's Critical

| Criteria | Your Argument |
|----------|---------------|
| RCE | "Remote code execution gives the attacker full control of the server, including access to the database, file system, and other services. This is the definition of Critical." |
| ATO chain | "Demonstrated account takeover of admin accounts leads to full system compromise. All user data, financial information, and business operations are at risk." |
| Mass data exposure | "Exposure of all users' data (not just one user) constitutes a mass breach. The cost of notification alone (under GDPR, SEC, or equivalent) exceeds typical critical thresholds." |

### Always-Rejected List

The following findings are nearly always rejected as N/A or informational:

| Finding | Why Rejected |
|---------|--------------|
| Missing HSTS header | Configuration issue, not a vulnerability |
| Missing CSP header | Without demonstrated XSS, it's informational |
| Self-XSS (requires user to paste code) | Not exploitable without social engineering |
| Missing rate limit on non-sensitive endpoint | Acceptable risk |
| Clickjacking on logout page | Impact: user logs out (not a security issue) |
| Password complexity not enforced | Typically a business decision |
| Missing account lockout | Often intentional to prevent DoS |
| Verbose server banner | Unless paired with a known CVE, informational |
| OPTIONS/TRACE method enabled | Without demonstrated impact, low/informational |
| Missing __Host- prefix on cookie | Defense-in-depth, not exploitable alone |
| TLS version allows old protocols | Without demonstrated MITM position |
| Username enumeration via timing | Usually accepted as known limitation |
| Self-XSS via filename upload | Requires user interaction, low impact |
| Open redirect with login requirement | Limited to authenticated users |
| "I could potentially..." (theoretical) | Prove it or don't report it |

### Conditionally-Valid-with-Chain Table

| Finding | Standalone | Chained With | Final Severity |
|---------|-----------|--------------|----------------|
| Open redirect | Low/Info | OAuth token theft, phishing | High/Critical |
| Reflected XSS with auth | Low/Medium | CSRF token theft, ATO | High |
| User enumeration | Info | Password reset abuse, credential stuffing | High |
| Missing rate limit on MFA | Low | Brute force MFA bypass | Critical |
| Verbose error message | Info | IDOR, enumeration | Medium/High |
| CORS misconfig | Low | XSS, data exfiltration | High |
| Prototype pollution (client) | Info | XSS via DOM manipulation | High |
| Cache poisoning (unauthenticated) | Medium | Victim visits poisoned page | High |
| Host header injection | Info | Password reset poisoning | Critical |
| Weak password policy | Info | Discovery of weak user passwords | High |

Always include a "chain potential" section in your report if your finding can be combined with another.

---

## Platform-Specific Triage Tactics

### HackerOne

#### Triage Process

```
Submission → Initial Review (1-7 days) → Triage Discussion → 
Bounty Decision → Disclosure (if eligible)
```

| Stage | Duration | What Happens |
|-------|----------|--------------|
| Initial Review | 1-7 days | Automated checks + human assignment |
| Triage Discussion | 1-14 days | May include back-and-forth with researcher |
| Bounty Decision | 1-30 days | Program determines severity and bounty |
| Disclosure | 90+ days | Report becomes public (if eligible) |

#### Response Times

- Average first response: 2-5 days
- Average time to bounty: 14-21 days
- Average time to triage: 5-10 days
- Mediation request response: 7-14 days

#### Dispute Process

If your report is marked as N/A or duplicate and you disagree:

1. **Reply to the report** — Add a comment with your differentiation arguments (use the templates in Section 7)
2. **Request the triager specify** — Ask the triager to identify exactly which prior report is the duplicate and how your finding maps to it
3. **Escalate to HackerOne support** — If you believe the triage was handled incorrectly, contact support@hackerone.com
4. **Request mediation** — HackerOne mediation is available for disputes about duplicate determination or severity

**Warning:** Only dispute if you have strong evidence. Repeated disputes without merit damage your reputation with both the program and the platform.

#### Mediation

HackerOne mediation is a formal process:

- Researcher requests mediation via the report interface
- HackerOne assigns a mediator (not from the program)
- Mediator reviews the report, the program's response, and the evidence
- Mediator's decision is final

Use mediation when:
- The triager marked your report as duplicate but won't share the reference
- The triager marked your report as out of scope based on an incorrect reading of policy
- The severity was downgraded without justification

### Bugcrowd

#### VRT Category Search

Bugcrowd uses the Vulnerability Rating Taxonomy (VRT) to determine baseline severity. Before submitting:

1. Find your vulnerability class in the [Bugcrowd VRT](https://bugcrowd.com/vrt)
2. Read the baseline severity
3. Read the "exceptional circumstances" section for possible upgrades

```markdown
### VRT Category Justification

**Bug Class:** IDOR (Insecure Direct Object Reference)
**VRT Baseline:** P3 (Medium)
**Exceptional Circumstances:** P2 (High) if the IDOR exposes PII or
financial data; P1 (Critical) if mass enumeration is possible

**My justification for P2/P1:** [Your reasoning]

**VRT Link:** https://bugcrowd.com/vrt#idor
```

#### Manual Severity Override

If the VRT default undersells your finding, submit a severity request:

```
I acknowledge that the VRT baseline for this issue is P3.
However, I believe a manual override is justified because:

1. [Impact is broader than typical: describe scope]
2. [Data exposed is more sensitive than typical: describe data types]
3. [Exploitation is easier than typical: describe access requirements]
4. [Chaining potential: describe what this enables]

Recommended severity: P1 (Critical)
```

#### QA vs Prod Distinction

Bugcrowd programs sometimes separate QA and production environments:

- **QA scope:** Test environments, staging, sandbox — typically lower bounties
- **Prod scope:** Live production — higher bounties

Always confirm which environment you're testing. If you find a bug in QA that also exists in prod, note this in your submission to potentially upgrade the severity.

### Intigriti

#### Triage Timeline

| Stage | Duration | Notes |
|-------|----------|-------|
| Submitted | 0-1 day | Automated confirmation |
| In review | 1-5 days | Intigriti team reviews |
| Waiting for program | 5-14 days | Program responds |
| Resolved | Varies | Bounty or rejection |

Intigriti reports typically get a faster initial response than HackerOne or Bugcrowd, but the program response time varies significantly.

#### Evidence Requirements

Intigriti is strict about evidence quality:

1. **Reproduction steps** must be numbered and specific
2. **Screenshots** required for visual bugs (XSS, open redirect)
3. **Video PoC** required for multi-step bugs (IDOR with chaining)
4. **curl commands** required for all API bugs
5. **Browser/version** must be specified

### Immunefi

#### Severity Calculation

Immunefi uses the Immunefi Vulnerability Severity Classification System (VSCS):

| Severity | Payout Range | Requirements |
|----------|--------------|--------------|
| Critical | $100k+ | Direct loss of funds, permanent network takeover |
| High | $10k-$100k | State manipulation with financial impact |
| Medium | $1k-$10k | Limited state manipulation without direct loss |
| Low | $500-$2k | No state change, limited information exposure |

#### Proof of Exploit Requirements

Immunefi requires a complete, working exploit:

1. **Smart contract bugs:** Provide a Foundry/Hardhat PoC that demonstrates the exploit end-to-end
2. **Network-level bugs:** Provide a script that demonstrates the attack
3. **Frontend bugs:** Provide a video PoC showing the exploit

Without a working PoC, Immunefi will mark the report as N/A even if the bug is valid.

---

## Post-Submission Monitoring

### What to Do After Submission

#### Monitor for Triage Status Changes (Daily)

Check the report status at least once per day. Set up notifications:

- HackerOne: Enable email notifications for report updates
- Bugcrowd: Check the dashboard daily
- Intigriti: Enable push notifications

Statuses to watch for:

| Status | Meaning | Your Action |
|--------|---------|-------------|
| Triaged | Issue accepted as valid | Wait for bounty |
| Needs more info | Triager needs clarification | Respond within 24 hours |
| Not applicable | Rejected | Review reason, consider dispute or move on |
| Duplicate | Already known | Review reference, learn from it |
| Resolved | Fixed | Check if you agree with resolution |

#### Respond to Triager Questions Within 24 Hours

When a triager asks for clarification:

1. **Read carefully** — Understand exactly what they need
2. **Provide exactly what's requested** — Not more, not less
3. **Be professional** — No frustration, no defensiveness
4. **If you can't provide it** — Explain why and offer alternatives

```markdown
Thank you for the review. To address your question about reproduction:

1. [Direct answer to their question]
2. [Additional evidence if helpful]
3. [Offer to provide more if needed]

Please let me know if this clarifies the issue or if you need
additional information.
```

#### Add Supplementary Evidence If Asked

If the triager asks for a video PoC, provide it within 24 hours. If they ask for additional accounts, create them immediately.

The longer you take to respond, the more likely the report is to languish or be marked as N/A.

#### When to Request Mediation (H1)

Request mediation only when:

1. The triager clearly misread the scope policy
2. The triager marked as duplicate but won't provide the reference report
3. The severity downgrade is unjustified and affects payout significantly
4. You have strong evidence to support your position

Do NOT request mediation for:
- Subjective severity disagreements (3.5 vs 4.0)
- Minor impact disagreements
- When the program is clearly acting in good faith

#### When to Accept N/A and Move On

Accept N/A and move on when:

1. The triager's reasoning is reasonable (even if you disagree)
2. You've exhausted the dispute process without result
3. The time investment in disputing exceeds the potential bounty
4. Your N/A rate is already high and further disputes may harm your reputation

### Learning from Rejected Duplicates

Every rejected duplicate is a learning opportunity:

#### Analyze Which Part of Your Research Was Incomplete

```markdown
## Post-Mortem: N/A Analysis

Report: h1://789013
Finding: IDOR on /api/v2/orders/{id}/cancel
Rejection Reason: Duplicate of #12345 (same root cause, different endpoint)

What I missed:
- Did not search for the root cause in existing disclosures
- Assumed v2 endpoint meant new code path
- Did not check if the fix for v1 covered v2

What I should have done:
- Searched for "authorization" or "orders" in disclosed reports
- Tested whether the v1 fix actually existed before testing v2
- Asked: "If this bug exists on v2, was v1 also vulnerable?"

Lesson learned: Always check the root cause, not the endpoint version.
```

#### Update Your Pre-Hunt Search Protocol

Add the missed search to your protocol:

```
Protocol Update: Added "root cause across all API versions" check.
Before reporting a bug on /api/v2/endpoint, always verify whether
the same root cause existed (and was fixed) on /api/v1/endpoint.
```

#### Document for Future Targeting of This Program

Add a note to your target-specific database:

```yaml
target: target.com
lessons_learned:
  - date: 2026-06-16
    report: h1://789013
    issue: v2 bug was duplicate of v1 fix gap
    action: Verify all API versions share the same auth layer before testing
  - date: 2026-06-01
    report: h1://789001
    issue: Triager couldn't reproduce because I didn't specify browser
    action: Always include browser/version in reproduction steps
```

---

## Building a Personal Anti-Duplicate Database

### Tracking What You've Already Found (and Got Paid For)

Create a local database (CSV, JSON, or Airtable):

```json
{
  "reports": [
    {
      "report_id": "h1://123456",
      "target": "target.com",
      "class": "IDOR",
      "endpoint": "/api/v1/orders/{id}",
      "severity": "High",
      "bounty": "$2500",
      "date": "2025-03-01",
      "root_cause": "Missing owner_id check in service layer",
      "tech_stack": "Ruby on Rails",
      "notes": "Fixed via adding .where(owner_id: current_user) to find method"
    },
    {
      "report_id": "h1://123789",
      "target": "target.com",
      "class": "XSS",
      "endpoint": "/search?q=",
      "severity": "Medium",
      "bounty": "$500",
      "date": "2025-06-15",
      "root_cause": "Unescaped output in search results template",
      "tech_stack": "React + Node.js",
      "notes": "Fixed via adding DOMPurify"
    }
  ]
}
```

Use this to:
- Avoid retesting endpoints you already submitted
- Identify which bug classes you're best at (focus more time there)
- Identify which bug classes keep getting N/A'd (improve or avoid)

### Tracking What You've Found (and Got N/A'd For)

Equally important — track failures:

```json
{
  "na_reports": [
    {
      "report_id": "h1://789013",
      "target": "target.com",
      "class": "IDOR",
      "endpoint": "/api/v2/orders/{id}/cancel",
      "date": "2026-06-16",
      "reason": "Duplicate of #12345",
      "lesson": "Check same root cause across API versions before reporting"
    },
    {
      "report_id": "h1://789014",
      "target": "other.com",
      "class": "Info Disclosure",
      "endpoint": "GET /api/health",
      "date": "2026-06-01",
      "reason": "Out of scope (health endpoint excluded)",
      "lesson": "Read scope policy more carefully"
    }
  ]
}
```

Pattern analysis:

```sql
-- Query your N/A database
SELECT reason, COUNT(*) as count FROM na_reports GROUP BY reason ORDER BY count DESC;

-- Results might show:
-- Duplicate: 6
-- Out of scope: 3
-- Cannot reproduce: 2
-- Known limitation: 1
```

If "Duplicate" is your top N/A reason, focus more on prior-art research.

### Tracking What Others Have Found (Public Disclosed)

Maintain a reference index of disclosed reports for your targets:

```yaml
target.com:
  disclosed_reports:
    - id: h1://123456
      class: IDOR
      endpoint: /api/v1/orders/{id}
      severity: High
      payout: $2500
      date: 2025-03-01
      status: Resolved

    - id: h1://123789
      class: XSS
      endpoint: /search?q=
      severity: Medium
      payout: $500
      date: 2025-06-15
      status: Resolved

  known_issue_patterns:
    - pattern: Missing owner_id check on order endpoints
      endpoints:
        - /api/v1/orders/{id} (fixed)
        - /api/v2/orders/{id}/cancel (reported but N/A as duplicate)
        - ? /api/v2/orders/{id}/refund (not yet tested — may still be open)
```

Use this to identify the *next* thing to test. If orders have been thoroughly tested, move to invoices, subscriptions, or warehouse endpoints.

### Using This Database to Identify Unduplicated Attack Surface

The database reveals gaps:

```yaml
target.com:
  tested_thoroughly:
    - Order endpoints (3 disclosed reports)
    - User profile endpoints (2 disclosed reports)
    - Search endpoints (1 disclosed report)

  not_yet_tested:
    - Invoice endpoints
    - Subscription endpoints
    - Webhook configuration endpoints
    - Admin dashboard endpoints
    - Export/import endpoints
    - Third-party integration endpoints
    - Mobile API endpoints
    - Beta features (if discoverable)
```

Focus your testing on the gap areas. They have fewer prior researcher eyes.

### GitHub Repo of Target-Specific Findings (Private)

Structure:

```
target-db/
├── targets/
│   ├── target-a.com/
│   │   ├── README.md              # Target overview
│   │   ├── disclosed-reports.md    # Index of known bugs
│   │   ├── attack-surface.md       # Map of endpoints
│   │   ├── tech-stack.md           # Framework versions
│   │   ├── my-reports/            # Your submissions
│   │   │   ├── 2025-03-01-idor.md
│   │   │   └── 2025-06-15-xss.md
│   │   └── na-reports/            # Your N/A'd submissions
│   │       └── 2026-06-16-idor-duplicate.md
│   └── target-b.com/
│       └── README.md
├── patterns/
│   └── idor-patterns.md           # Common IDOR patterns across targets
└── scripts/
    ├── prior-art.sh               # Prior art search automation
    └── duplicate-check.sh         # Quick search across your DB
```

This is your personal intelligence repository. The more you maintain it, the less time you spend on duplicate research for each new target.

---

## Case Studies

### Case Study 1: The GraphQL Variant That Wasn't a Duplicate

**Target:** A SaaS project management platform
**Researcher Experience Level:** Intermediate (6 months of bug bounty)

**The Scenario:**

The researcher found an IDOR on `/api/v1/tasks/{id}` — any authenticated user could read any task by changing the task ID. Before submitting, they searched HackerOne disclosed reports and found:

- Report #45678: "IDOR on GET /api/v1/tasks/{id}" — same endpoint, same bug
- Status: Fixed, bounty paid, report disclosed

The researcher almost moved on — but then checked the GraphQL endpoint:

```graphql
query {
  task(id: 456) {
    id title description assignee { email }
    project { name owner { email } }
  }
}
```

The GraphQL resolver had the *same* missing authorization check. The REST fix used middleware, but the GraphQL resolver bypassed that middleware entirely.

**The Submission:**

The researcher submitted the GraphQL variant with a differentiation statement:

```
Report #45678 covered the REST endpoint. The fix was applied at the
REST middleware layer. My submission covers the GraphQL resolver,
which is a separate code path that does not use the REST middleware.

Root cause is the same (missing authorization), but the fix for #45678
did not address this vector. This is a defense-in-depth bypass.

To verify: the fix for #45678 added middleware that checks
`req.params.id === req.user.id`. GraphQL does not use `req.params` —
it uses resolver arguments. The GraphQL resolver `task(id: Int!)`
queries the database directly without any ownership check.
```

**Result:**

The program accepted it as a separate finding and paid a bounty. They also expanded their fix to cover GraphQL resolvers.

**Lesson:** Always check alternative API interfaces (GraphQL, WebSocket, gRPC) for the same bug. If the fix was applied to REST middleware, other interfaces may still be vulnerable.

### Case Study 2: The Export Endpoint That Slipped Through

**Target:** A CRM platform with a mature bug bounty program (3+ years)
**Researcher Experience Level:** Advanced (2+ years)

**The Scenario:**

The researcher found an IDOR on the CSV export endpoint: `GET /api/contacts/export.csv`. The endpoint allowed any authenticated user to export ALL contacts in the organization, not just their own.

Before submitting, the researcher searched:

1. H1 disclosed: Found 3 related IDOR reports on the same program
2. All 3 were on REST endpoints (`/api/contacts/{id}`, `/api/contacts/batch`)
3. None covered the export endpoint

**Differentiation:**

```
Known bug #1: IDOR on GET /api/contacts/{id} — read individual contact
Known bug #2: IDOR on POST /api/contacts/batch — read batch of contacts
Known bug #3: IDOR on PUT /api/contacts/{id} — modify contact

My finding: IDOR on GET /api/contacts/export.csv — download ALL contacts

The export endpoint generates a CSV of the entire contact database.
The query behind it is:
  SELECT * FROM contacts WHERE org_id = ? (organization-level scope)

It should be:
  SELECT * FROM contacts WHERE owner_id = ? (user-level scope)

This is distinct from the known bugs because:
1. The fix for known bugs added owner_id checks to individual queries
2. The export endpoint uses a completely different code path
   (CSV generation service vs REST controller)
3. Impact is broader: export reveals ALL contacts in one action,
   not one-at-a-time
```

**Result:**

The program accepted it as High severity ($3,500 bounty). They fixed the export query and added a separate admin export endpoint.

**Lesson:** Export endpoints are frequently overlooked because they're considered "admin utilities." Always test them for authorization scope.

### Case Study 3: The Near-Duplicate That Required Defense

**Target:** A fintech startup on HackerOne (program running 8 months)
**Researcher Experience Level:** Intermediate

**The Scenario:**

The researcher found a race condition on the checkout endpoint `POST /api/checkout`. By sending 50 parallel requests, they could purchase an item multiple times but only get charged once (or get a quantity discount multiple times).

Before submitting, they searched H1 disclosed and found:
- Report #78901: "Race condition on POST /api/orders" — similar bug class, different endpoint

**The Challenge:**

The triager marked it as duplicate of #78901, saying "both are race conditions in the order flow."

**The Defense:**

The researcher prepared a detailed differentiation:

```
Report #78901 describes a race condition in order *creation*
(POST /api/orders) where concurrent requests create multiple orders
from a single cart.

My finding describes a race condition in the *checkout/payment* flow
(POST /api/checkout) where concurrent requests bypass the inventory
deduction check.

These are distinct because:

1. Code path: Orders and checkout use different services
   (OrderService vs PaymentService)

2. Root cause: #78901's root cause was missing uniqueness constraint
   on order_number. My root cause is missing optimistic locking on
   inventory_quantity.

3. Impact: #78901 creates ghost orders. My finding allows
   purchasing more items than are in stock (inventory bypass).

4. Fix: #78901 was fixed with a database constraint. My finding
   requires atomic inventory updates (e.g., UPDATE ... SET 
   quantity = quantity - 1 WHERE quantity > 0).

I've attached a comparison table:
| Aspect | #78901 | My Finding |
|--------|--------|------------|
| Endpoint | POST /api/orders | POST /api/checkout |
| Service | OrderService | PaymentService |
| Root cause | Duplicate order creation | Race condition on inventory |
| Impact | Ghost orders | Overselling / inventory bypass |
| Fix type | DB constraint | Atomic update |

I respectfully request that my finding be re-evaluated as a distinct
issue with a separate root cause.
```

**Result:**

The triager accepted the differentiation and re-classified it as a separate finding. Payout: $2,000 (High).

**Lesson:** When a triager marks near-duplicate, don't just accept it — provide concrete, technical differentiation. A comparison table makes it easy for the triager to see the difference at a glance.

### Case Study 4: The Successful Severity Upgrade

**Target:** A large e-commerce platform
**Researcher Experience Level:** Advanced

**The Scenario:**

The researcher found an IDOR on `GET /api/orders/{id}` that returned order details including the customer's email, phone, and shipping address. The triager initially marked it as Medium (consistent with VRT baseline for IDOR).

**The Upgrade Request:**

```
I appreciate the triage assessment. However, I believe a severity
upgrade is warranted based on the following:

1. Data sensitivity: The endpoint exposes:
   - Customer email (PII)
   - Phone number (PII)  
   - Full shipping address (PII)
   - Order items and prices (commercial confidentiality)
   - Discount codes (financial impact)
   
2. GDPR implications: Under GDPR, exposure of email + phone + address
   constitutes a personal data breach requiring notification to the
   supervisory authority within 72 hours.

3. Enumeration is trivial: Order IDs are sequential 6-digit integers.
   An attacker can enumerate 1,000 orders per minute (well below any
   rate limit). That's 100,000+ customer records per hour.

4. Discount code theft: The exposed discount codes can be used by the
   attacker to make purchases at reduced prices, causing direct
   financial loss.

Per Bugcrowd VRT exceptional circumstances:
- PII exposure → upgrade from P3 to P2
- Financial data exposure → upgrade from P3 to P2
- Mass enumeration possible → upgrade from P3 to P1

I recommend at minimum P2 (High), and P1 (Critical) if mass
enumeration is demonstrated.
```

**Result:** The program upgraded to High and paid $4,000.

**Lesson:** Don't accept the initial severity if there's a strong case for upgrade. Provide specific, data-driven arguments referencing the platform's own severity guidelines.

### Case Study 5: The Fresh-State Reproduction That Saved a Report

**Target:** A social media platform
**Researcher Experience Level:** Beginner

**The Scenario:**

The researcher found a stored XSS in the user bio field. After reporting, the triager responded: "Cannot reproduce. The bio appears to be sanitized."

**The Response:**

```
Thank you for testing. I may not have provided sufficient environment
detail. Here is the exact reproduction from a completely fresh state:

1. Create a NEW account (must be less than 24 hours old — the 
   sanitization was added for accounts created before March 2026)
2. Go to Settings → Profile → Bio
3. Paste: <img src=x onerror=alert(document.cookie)>
4. Save
5. View your public profile page (not the settings page)
6. The bio field renders the XSS

Key details:
- The sanitization was added retroactively for existing accounts
  but is NOT applied to new accounts
- The settings page previews the bio (no XSS there)
- The public profile page renders the bio (XSS triggers)
- I tested on Chrome 120, Windows 11

Video PoC attached showing the full flow from account creation to XSS.
```

**Result:** The triager reproduced successfully and accepted the report ($1,500).

**Lesson:** The most common reproduction failure is missing environment details. If the triager can't reproduce, provide more specific instructions — including exact account state, timing, and browser.

---

## Anti-Duplicate Checklist

### Pre-Hunt Search Checklist

- [ ] Search HackerOne disclosed reports for target + vulnerability class
- [ ] Search Bugcrowd disclosed reports for target
- [ ] Search Intigriti disclosed reports for target
- [ ] Search GitHub issues for target's repos with `security` label
- [ ] Search CVE/NVD database for target tech stack components
- [ ] Google dork: `site:target.com "security" "vulnerability" "advisory"`
- [ ] Google dork: `site:hackerone.com/reports target.com`
- [ ] Google dork: `site:forum.bugcrowd.com target.com`
- [ ] Check security.txt acknowledgements for previously reported issues
- [ ] Wayback Machine: historical security pages and reports
- [ ] Twitter search: `target.com bug bounty` mentions
- [ ] Telegram/Discord: check community archives for target discussions
- [ ] Run `prior_art.sh` (or equivalent automation) against target
- [ ] Build target-specific known-vulnerability database entry
- [ ] Identify which bug classes are likely underexplored on this program

### During-Hunt Awareness Checklist

- [ ] Skip the obvious endpoints everyone tests first (focus on new features)
- [ ] Before investing >1 hour on a finding, check if the endpoint was recently added
- [ ] Check if the same endpoint exists on other API versions (v1, v2, v3)
- [ ] Check alternative interfaces: GraphQL, WebSocket, gRPC, mobile
- [ ] Document every test you perform (endpoint, parameter, result)
- [ ] Before pivoting to a new area, check disclosed reports for that area
- [ ] If you find a bug on endpoint X, check if endpoint Y (similar function) has the same bug — but verify each is novel before submitting
- [ ] Track your own findings to avoid resubmitting your own previous reports
- [ ] If a finding feels "too obvious," it's probably already been found
- [ ] Ask yourself: "Would an automated scanner find this?" If yes, it's likely duplicate

### Pre-Submission Deep Search Checklist (15-Minute Protocol)

- [ ] Step 1: H1/Bugcrowd disclosed search for target + vuln class (2 min)
- [ ] Step 2: GitHub issues search for security labels (2 min)
- [ ] Step 3: CVE/NVD search for component + vuln type (2 min)
- [ ] Step 4: Search changelogs/release notes for "security" mentions (1 min)
- [ ] Step 5: Search community Discord/Slack archives (1 min)
- [ ] Step 6: Search Twitter for target + bug bounty mentions (1 min)
- [ ] Step 7: Check if same pattern reported for similar tech stack (1 min)
- [ ] Step 8: Google dork the exact payload you plan to use (1 min)
- [ ] Step 9: Check if the finding is in a "known limitations" doc (1 min)
- [ ] Step 10: Search security.txt acknowledgements (1 min)
- [ ] Document search results in report appendix
- [ ] If any search matches, stop and evaluate: is your variant truly different?
- [ ] Run `prior_art.sh` one more time before the final submit

### Evidence Package Checklist

- [ ] Step-by-step reproduction from fresh state (no assumptions)
- [ ] Two accounts demonstrated (if applicable)
- [ ] Request/response pairs formatted and annotated
- [ ] curl commands provided for each step
- [ ] Before vs after comparison shown
- [ ] Video PoC < 60 seconds, annotated with step numbers
- [ ] Screenshots with PII redacted (cookies, emails, names)
- [ ] HAR file sanitized (no Cookie, Set-Cookie, Authorization headers)
- [ ] Impact statement written (business impact, not just technical)
- [ ] Scope citation (which part of policy the finding falls under)
- [ ] CVSS 3.1 calculation with metric breakdown
- [ ] Chain potential documented (if applicable)
- [ ] Differentiation from known issues (if applicable)
- [ ] Prior-art search results appendix

### Post-Submission Monitoring Checklist

- [ ] Monitor report status daily
- [ ] Respond to triager questions within 24 hours
- [ ] Add supplementary evidence within 24 hours if asked
- [ ] Check for severity/triage updates
- [ ] If marked N/A or duplicate:
  - [ ] Read the reason carefully
  - [ ] If valid N/A, learn and move on
  - [ ] If questionable, prepare differentiation response (Section 7 templates)
  - [ ] If H1, consider mediation if strong case
- [ ] If severity downgrade:
  - [ ] Prepare upgrade request with data-driven arguments
  - [ ] Reference platform VRT exceptional circumstances
- [ ] Update personal anti-duplicate database
- [ ] Document lessons learned for future targeting
- [ ] If paid: add to tracking database for future reference
- [ ] If N/A: add to N/A database with reason and lesson learned

---

## Reference

- [HackerOne Duplicate Policy](https://docs.hackerone.com/articles/report-duplication/)
- [Bugcrowd VRT](https://bugcrowd.com/vrt)
- [Intigriti Submission Guidelines](https://www.intigriti.com/submission-guidelines)
- [Immunefi Severity Classification](https://immunefi.com/severity-classification-system/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackerOne Mediation Process](https://docs.hackerone.com/en/articles/8498110-mediation)
- See also: `agents/validator.md`, `agents/triage-defender.md`, `agents/evidence-reviewer.md`, `agents/p1-validator.md`, `agents/triage-readiness.md`
