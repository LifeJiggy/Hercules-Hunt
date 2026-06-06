---
name: scope-master
description: Program scope management guide for bug bounty hunters. Covers scope parsing, wildcard interpretation, out-of-scope asset handling, scope-chaining rules, and how to handle scope ambiguities. Use when starting a new program, verifying asset eligibility, or resolving scope questions. Chinese trigger: 范围、scope、in-scope、out-of-scope、wildcard、资产范围
---

# Scope Master

Program scope interpretation and asset eligibility.

---

## SCOPE PHILOSOPHY

```
SCOPE DECISION FLOW:
1. READ — Program's scope definition verbatim
2. PARSE — Extract domains, IP ranges, asset types
3. INTERPRET — Apply wildcard rules and scope language
4. VERIFY — Check each target asset individually
5. DOCUMENT — Record per-asset scope decision
```

### Scope rules

| Scope type | Meaning | Action |
|---|---|---|
| `*.target.com` | All subdomains of target.com | Test all subdomains |
| `target.com` | Root domain only | Do NOT test subdomains unless stated |
| `www.target.com` | Single subdomain | Only test that host |
| `target.com/api/*` | Specific path only | Only test /api paths |
| `target.com` (production) | Prod only | Do NOT test staging/dev |
| `*` target.com and *.target.com | Both root and subdomains | Full scope |
| IP range 1.2.3.4/24 | CIDR block | Test IPs in range |
| Mobile app bundle: com.target.app | Mobile testing in scope | Test via proxy, API, deobfuscation |

---

## SCOPE LANGUAGE INTERPRETATION

### Common scope terms and their meanings

| Term | Meaning | Edge cases |
|---|---|---|
| "All domains" | Every domain owned by target | Usually doc'd by whois, not assumed wildcard |
| "All subdomains" | `sub.target.com` where sub can be anything | Does NOT include root `target.com` unless also listed |
| "Root domain" | The bare domain target.com | Subdomains out of scope unless separately listed |
| "Production" | Live customer-facing systems | Staging/dev/test out of scope by default |
| "Staging" | Explicitly listed pre-production environments | Can include real data; worth testing |
| "Mobile app" | iOS/Android app + associated APIs | Test via proxy, verify in-scope domains |
| "API" | REST/GraphQL endpoints on in-scope domains | Excludes third-party APIs unless owned by target |
| "SSL/TLS" | Certificate, configuration only | Does NOT grant testing of the service itself |
| "Source code" | Public repos only, usually | Private repos are out of scope |
| "Acquisitions" | If scope lists "including acquired companies" | Check for separate scope for acquisitions |

### Wildcard interpretation

```
*.target.com:
- Matches: api.target.com, dev.target.com, admin.target.com, z.target.com
- Does NOT match: target.com (root), sub.sub.target.com (technically yes, second-level sub)
- Edge: Does target.com resolve when you visit *.target.com? Some programs list both.

target.com only:
- Do NOT test api.target.com
- Do NOT test cdn.target.com
- Do NOT test sub.target.com
- If api.target.com appears in JS on target.com: flag to program before testing

www.target.com:
- ONLY test www.target.com
- Do NOT test app.target.com or api.target.com
```

### Path-scoped programs

```
Scope: "target.com/api/*"
Allowed: GET https://target.com/api/users
Allowed: POST https://target.com/api/users
NOT allowed: GET https://target.com/admin (out of scope)
NOT allowed: GET https://target.com/ (root page)

Rule: If the path in scope is /api/*, the root page is out of scope
even if it links to /api.
```

### IP-scoped programs

```
Scope: "1.2.3.4 - 5.6.7.8"
OR
Scope: "1.2.3.0/24"

Rules:
- Test only the listed IPs/ranges
- Do NOT test hostnames resolving to those IPs unless the hostname is also in scope
- Check if PTR records resolve back; confirm scope before testing
- If scope lists a domain AND its resolves-to IP, test both
```

---

## OUT-OF-SCOPE ASSET HANDLING

### How to identify out-of-scope assets

```
Out of scope:
- Internal hostnames: *.internal.target.com, corp.target.com
- Third-party services: Stripe, Google, Salesforce (unless YOUR integration is in scope)
- Dev/staging environments unless listed
- Physical assets (offices, hardware)
- Employee emails (social engineering usually out of scope)
- Social media accounts of employees
- Open redirects to out-of-scope domains
```

### Third-party service rules

```
General rule:
If the service is something the company USES (not owns), and the bug is IN
the service itself → out of scope.

Examples:
- Stripe payment processing bug → Stripe's problem, not target's
- Google auth bug → Google's problem
- AWS S3 bucket owned by target → IN SCOPE (target owns it)
- AWS S3 bucket named after target but owned by someone else → OUT OF SCOPE (check ACL attribution)

Exception: If the target's INTEGRATION with the service has a bug
(e.g., target.com/client_secret in their mobile app), that IS in scope.
Exception: If you find a YOUR-service credential in target's JS → 
the credential itself is a finding (disclosed, not stolen).
```

### Scope edge case: redirects

```
Scenario 1: target.com redirects to evil.com (open redirect)
- Finding: open redirect on target.com → in scope
- Chain: victim.com → attacker.com redirect → redirect → oauth.target.com → code theft
- If final chain step lands on in-scope domain: report
- If final chain step lands on out-of-scope domain: kill or report only the in-scope primitive

Scenario 2: SSRF to out-of-scope internal host
- SSRF is on in-scope target.com
- SSRF reaches out-of-scope internal host (e.g., 10.0.0.5)
- If data FROM out-of-scope host is returned by in-scope app: 
  - Primitive (SSRF itself) is in scope
  - The fact that it reached an internal host is the impact
  - Report the SSRF; don't access the out-of-scope host's data extensively

Scenario 3: OAuth redirect_uri on staging target
- If staging is out of scope and redirect_uri is on staging: 
  - The OAuth redirect chain starts on an out-of-scope domain
  - The OAuth authorization server may be in scope
  - Check if the client_id itself is in-scope owned
  - If the OAuth server (authorization server, not redirect URI) is in scope: the redirect behavior is in scope
  - If redirect URI is the only thing out of scope: report the redirect as a primitive finding
```

---

## SCOPE PARSING CHECKLIST

For every new program, run this checklist before you start testing:

```
[ ] 1. Exact domain(s) listed
    - Root domain? Subdomains? Both?
    - Are wildcards used? (*.target.com)

[ ] 2. IP ranges listed
    - CIDR notation?
    - Ports specified?

[ ] 3. Path restrictions
    - Specific paths only?
    - Or full domain?

[ ] 4. Asset types
    - Web app only?
    - Mobile app?
    - API only?
    - SSL/TLS only?

[ ] 5. Exclusions
    - Explicitly listed out-of-scope items?
    - Testing restrictions?

[ ] 6. Out-of-scope sections
    - Third-party services?
    - Social engineering?
    - Physical attacks?
    - DDoS?
    - Automated scanning restrictions?

[ ] 7. Special notes
    - Rate limits?
    - No destructive testing?
    - Test account requirements?
    - Time windows?
```

---

## SCOPE AMBIGUITY RESOLUTION

### When scope is unclear: ASK FIRST

Program contact methods:
- HackerOne: Use "Ask a question" button
- Bugcrowd: Program Q&A section
- Intigriti: Program contact form
- Email: Provided on program page

**Good scope question template:**
```markdown
Hi team, quick scope clarification:

I found a finding on `staging-api.target.com`. The program scope
lists `*.target.com` — does this include staging subdomains, or
only production subdomains?

The finding is a [brief description] and the data returned appears
to be from production user records.

Thanks,
[Your name]
```

### Ambiguity patterns

| Pattern | Interpretation | Action |
|---|---|---|
| "Production and pre-production" | Includes staging/dev | Test staging |
| "Production environments" | Usually excludes staging | Check with program |
| "All subdomains" | Includes staging subdomains | Test if staging subdomains exist |
| "Not explicitly listed = out of scope" | Strict mode | Only test listed items |
| "In scope includes acquisitions" | Subsidiaries in scope too | Check acquisition list |

---

## SCOPE-CHAINING RULES

### Chain with out-of-scope elements

```
Chain must start and end in scope for the FINDING to be in scope.

Valid chain:
In-scope SSRF → out-of-scope internal host returns production credentials
Result: SSRF is in-scope finding; the "reached internal host" is the impact.

Invalid chain:
Out-of-scope staging domain → returns data accessible from in-scope domain
Result: Kill unless there's an independent in-scope primitive.

Rule: Does the in-scope input directly cause the impact?
If the in-scope primitive causes the out-of-scope element to be queried
and data from that query is RETURNED to the in-scope caller, the
SSRF itself is in scope. Do NOT continue testing the out-of-scope
element independently.
```

### Scope in multi-tenant programs

```
Some programs have "Group X" scope that includes multiple domains:
- target.com
- target-eu.com
- target-apac.com

Rule: Treat each listed domain as independent unless stated otherwise.
An IDOR on target-eu.com is a separate finding from target.com.
```

---

## SCOPE CHANGE HANDLING

### When scope expands mid-engagement

```
Scenario: Program expands scope to include new subdomains
Action:
1. Note the expansion date
2. Re-run recon on new subdomains
3. Check if any earlier findings now apply to new assets
4. Update your testing log

Scenario: Program contracts scope (removes an asset)
Action:
1. Check if your submitted findings were on the removed asset
2. If yes, notify the program: "Finding X is on [removed asset]. Please advise if I should retract."
3. Stop testing on removed asset immediately
```

### Scope on resubmitted findings

```
Scenario: You found a bug on out-of-scope staging, program adds staging to scope
Action:
1. Re-test on newly in-scope staging
2. Submit as new finding
3. Reference your earlier out-of-scope testing in notes

Scenario: You found a bug on in-scope asset, program narrows scope
Action:
1. Check if the asset is still in scope
2. If removed: contact program; they may honor the original finding
3. If not: kill if you cannot test on a still-in-scope asset
```

---

## COMMON SCOPE MISTAKES

### Mistake 1: Assuming subdomains are in scope

```
BAD ASSUMPTION: "If target.com is in scope, api.target.com is too."
CORRECT: Check scope list for explicit subdomain wildcard or listed subdomains.

Fix: Always verify each target hostname individually.
```

### Mistake 2: Testing CDN edge nodes

```
Scenario: Static content served via Cloudflare/CloudFront on *.target.com
CDN edge node: xyz123.cloudfront.net pointing to target.com

Rule: If the CDN domain is not target.com or *.target.com, it is out of scope
even if it serves target.com content. Test via target.com (in scope) instead.
```

### Mistake 3: Testing third-party integrations

```
BAD: Finding XSS in Google Analytics script served from google.com
- google.com is not target.com; this is Google's bug

BAD: Finding CSRF on stripe.com checkout
- Strip.com is not target's integration; it's Stripe's service

GOOD: Finding XSS in target.com's custom payment form that posts to stripe.com
- The bug is in target's form rendering → in scope

GOOD: Finding client_secret in target's mobile app
- Disclosure of the secret is a finding about target's app → in scope
```

### Mistake 4: Testing deleted scope items

```
If scope lists "asset removed on 2025-01-15" and you're testing on 2025-01-20:
- Do NOT test the removed asset
- Do NOT submit findings on the removed asset
- Contact program about earlier findings on that asset

Programs that don't remove assets cleanly may grandfather existing findings.
```

---

## SCOPE MASTERY CHECKLIST

Before starting each program:

```
INITIAL SETUP:
[ ] Read full program scope page
[ ] Note: in-scope domains, IPs, paths, asset types
[ ] Note: explicitly excluded items
[ ] Note: testing restrictions (rate limits, no destructive ops)
[ ] Note: special requirements (test accounts, etc.)

PER-ASSET CHECK:
[ ] Is hostname on in-scope list?
[ ] Or is it a wildcard match?
[ ] Or is it explicitly excluded?
[ ] If ambiguous: ASK before testing

CHAIN CHECK:
[ ] Does the chain start on an in-scope asset?
[ ] Does the chain end on an in-scope asset?
[ ] Is the out-of-scope element in the chain just the payload, or the identity?

REFRESH:
[ ] Re-check scope page weekly (programs update scope)
[ ] Re-check before submitting each finding
[ ] Re-check after program announces scope changes
```

---

## Final scope rules

1. **Scope language wins** — if it says "production," staging is out.
2. **Wildcards are not universal** — `*.target.com` does not include `target.com` root.
3. **Ask before testing when unclear** — ambiguity resolution via program contact is professional.
4. **Stop testing on scope changes** — when an asset is removed, stop immediately.
5. **Document per-asset scope decisions** — your triage notes should justify each tested asset.
6. **Chains with out-of-scope elements need careful framing** — report in-scope primitive; describe the out-of-scope impact without claiming independent testing.
7. **Third-party services are out of scope** — unless the target's integration with them has the bug.
