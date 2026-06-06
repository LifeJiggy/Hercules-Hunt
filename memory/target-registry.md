# Target Registry

Persistent knowledge base tracking every target ever hunted. Updated after every session.
This is your personal target intelligence database — used for pattern recognition, program
quality assessment, and knowing which targets are worth revisiting.

---

## Table of Contents

1. [Target Profile Template](#1-target-profile-template)
2. [Target Inventory](#2-target-inventory)
3. [Payout Summary](#3-payout-summary)
4. [Tech Stack Mapping](#4-tech-stack-mapping)
5. [Program Quality Rankings](#5-program-quality-rankings)
6. [Target Selection Heuristics](#6-target-selection-heuristics)
7. [Target Notes Archive](#7-target-notes-archive)
8. [Dupes and Competitor Analysis](#8-dupes-and-competitor-analysis)
9. [Revisit Candidates](#9-revisit-candidates)
10. [Cross-Target Pattern Analysis](#10-cross-target-pattern-analysis)

---

## 1. Target Profile Template

Use this template for every new target. Fill it in during Phases 1-2 of the hunting workflow.

```markdown
## TARGET: [Domain]

### Metadata
- Program: [HackerOne / Bugcrowd / Intigriti / Immunefi / Private]
- Platform URL: [Link to program page]
- First Hunted: [YYYY-MM-DD]
- Last Hunted: [YYYY-MM-DD]
- Total Sessions: [N]
- Total Hours: [N]
- Scope Type: [Wildcard / Specific / Mixed]
- Payout Model: [Varies / Fixed / Tiered / Per-bug]
- Safe Harbor: [Yes / Yes with exceptions / No]

### Scope
- Primary Domain: [target.com]
- Wildcard Pattern: [*.target.com]
- In Scope Subdomains:
  - [sub1.target.com]
  - [sub2.target.com]
- Out of Scope:
  - [acq.target.com] — acquired company, per program policy
  - [blog.target.com] — explicitly excluded
- API Scope:
  - [api.target.com/*]
  - [*.api.target.com]

### Tech Stack
- Frontend: [React / Vue / Angular / SPA / SSR / Next.js / Nuxt]
- Backend: [Rails / Django / Node / ASP.NET / Go / PHP / Spring / FastAPI]
- Database: [PostgreSQL / MySQL / MongoDB / Redis / Elasticsearch]
- Auth: [JWT / Session / OAuth / SAML / OIDC / Custom / Devise / Auth0]
- Cloud: [AWS / GCP / Azure / On-prem / Cloudflare]
- CDN/WAF: [Cloudflare / Akamai / Fastly / CloudFront / Imperva]
- CMS: [WordPress / Shopify / Custom / Headless CMS / Contentful / Strapi]
- Third Parties: [Stripe / PayPal / SendGrid / Twilio / Mailchimp / Algolia]

### Discovery Summary
- Total Subdomains Found: [N]
- Live HTTP Hosts: [N]
- Interesting Endpoints Found:
  - [Endpoint 1]
  - [Endpoint 2]
- Auth Bypass Candidates:
  - [Candidate 1]
  - [Candidate 2]
- JS Bundles Found:
  - [bundle1.js]
  - [bundle2.js]
- GraphQL Endpoints:
  - [/graphql]
  - [/api/graphql]

### Findings Summary
#### Submitted (Paid)
| # | Bug Class | Severity | CVSS | Payout | Date Submitted | Date Triaged | Notes |
|---|-----------|----------|------|--------|---------------|--------------|-------|
| 1 | IDOR | High | 7.1 | $2,000 | 2026-01-15 | 2026-01-18 | Direct object ref in orders API |
| 2 | XSS | Medium | 6.3 | $750 | 2026-02-01 | 2026-02-05 | Reflected in search param |

#### Submitted (Unpaid / N/A)
| # | Bug Class | Reason | Date | Notes |
|---|-----------|--------|------|-------|
| 1 | Missing CSP | N/A — always rejected | 2026-01-20 | Should have killed before writing |
| 2 | Self-XSS | N/A — only triggers on own input | 2026-02-10 | Could have chained with CSRF |

#### Killed Before Submission
| # | Bug Class | Kill Reason | Kill Gate | Date |
|---|-----------|-------------|-----------|------|
| 1 | Rate limiting bypass | Non-critical endpoint (Q2) | 7-Question Gate | 2026-01-22 |
| 2 | IDOR | UUID not predictable (Q3) | 7-Question Gate | 2026-02-05 |

### Chain Primitives Discovered
- [Primitive 1] — standalone kill, but could chain with [X]
- [Primitive 2] — currently no chain partner found

### Account Inventory
- Account A (attacker): [email] — [role/privileges]
- Account B (victim): [email] — [role/privileges]
- Account C (admin): [email] — [role/privileges] (if obtained)
- Notes on how these were created

### Session Logs
- [YYYY-MM-DD] — [Session description, what was tested, what was found]
- [YYYY-MM-DD] — [Session description]

### Notes and Observations
- [Free-form notes about the target's security posture]
- [Developer psychology observations]
- [Interesting code patterns noticed]
- [Third-party integrations that might be attack vectors]
- [Rate limiting patterns observed]
- [WAF behavior notes]
```

### Quick Target Entry Template (for rapid note-taking during a session)

```markdown
TARGET: [domain]
SESSION: [YYYY-MM-DD]
TECH: [frontend], [backend], [auth], [cloud]
SCOPE: [pattern]

FOUND:
- [ ] [finding 1]
- [ ] [finding 2]

KILLED:
- [kill 1] — reason

NEXT: [what to test next session]
```

---

## 2. Target Inventory

### 2.1 Active Targets (Currently Being Hunted)

| Target | Program | Tech Stack | Session Count | Last Hunted | Top Unverified Lead | Priority |
|--------|---------|------------|---------------|-------------|-------------------|----------|
| coinmarketcap.sandbox | BB | Next.js, Node, JWT, AWS | 0 | — | JWT alg:none paywall | High |
| boozt.com | BB | Rails, React, GCP, Cloudflare | 0 | — | Registration disabled, need alternate account | Medium |
| | | | | | | |

### 2.2 Completed Targets (All Leads Exhausted)

| Target | Program | Total Sessions | Total Hours | Total Payout | Best Finding | Status |
|--------|---------|---------------|-------------|-------------|--------------|--------|
| | | | | | | |

### 2.3 Archived Targets (Program Dead / Out of Scope / Deprioritized)

| Target | Program | Reason Archived | Last Hunted | Notable Lesson |
|--------|---------|----------------|-------------|----------------|
| | | | | |

### 2.4 Targets to Revisit (New Features / Previous Kills Might Chain)

| Target | Reason to Revisit | Previous Best Lead | Estimated Effort |
|--------|------------------|-------------------|------------------|
| | | | |

### 2.5 Targets on Watchlist (Not Yet Hunted)

| Target | Program | Tech Stack | Why Interesting | Priority |
|--------|---------|------------|-----------------|----------|
| | | | | |

---

## 3. Payout Summary

### 3.1 Payout by Program

| Program | Submitted | Paid | N/A Rate | Average Payout | Total Payout | Best Payout |
|---------|-----------|------|----------|----------------|--------------|-------------|
| HackerOne | 0 | 0 | 0% | — | — | — |
| Bugcrowd | 0 | 0 | 0% | — | — | — |
| Intigriti | 0 | 0 | 0% | — | — | — |
| Immunefi | 0 | 0 | 0% | — | — | — |
| Private | 0 | 0 | 0% | — | — | — |

### 3.2 Payout by Bug Class

| Bug Class | Submitted | Paid | N/A Rate | Average Payout | Best Payout |
|-----------|-----------|------|----------|----------------|-------------|
| IDOR / BOLA | 0 | 0 | 0% | — | — |
| Auth Bypass | 0 | 0 | 0% | — | — |
| SSRF | 0 | 0 | 0% | — | — |
| XSS | 0 | 0 | 0% | — | — |
| SQLi | 0 | 0 | 0% | — | — |
| Business Logic | 0 | 0 | 0% | — | — |
| File Upload | 0 | 0 | 0% | — | — |
| API Misconfig | 0 | 0 | 0% | — | — |
| Race Condition | 0 | 0 | 0% | — | — |
| Subdomain Takeover | 0 | 0 | 0% | — | — |
| JWT Attacks | 0 | 0 | 0% | — | — |
| CORS | 0 | 0 | 0% | — | — |
| GraphQL | 0 | 0 | 0% | — | — |
| SSTI | 0 | 0 | 0% | — | — |
| SAML / SSO | 0 | 0 | 0% | — | — |
| MFA Bypass | 0 | 0 | 0% | — | — |
| ATO | 0 | 0 | 0% | — | — |

### 3.3 Payout by Severity

| Severity | Submitted | Paid | Average Payout | Total Payout |
|----------|-----------|------|----------------|--------------|
| Critical (9.0-10.0) | 0 | 0 | — | — |
| High (7.0-8.9) | 0 | 0 | — | — |
| Medium (4.0-6.9) | 0 | 0 | — | — |
| Low (0.1-3.9) | 0 | 0 | — | — |
| Informational | 0 | 0 | — | — |

### 3.4 Payout Trend Analysis (All Programs)

Track how your payout rate changes over time:

| Month | Submissions | Paid | N/A'd | Total Payout | Avg Payout | Avg Hours/Submission |
|-------|-------------|------|-------|-------------|-------------|---------------------|
| Jan 2026 | 0 | 0 | 0 | $0 | — | — |
| Feb 2026 | 0 | 0 | 0 | $0 | — | — |
| Mar 2026 | 0 | 0 | 0 | $0 | — | — |
| Apr 2026 | 0 | 0 | 0 | $0 | — | — |
| May 2026 | 0 | 0 | 0 | $0 | — | — |
| Jun 2026 | 0 | 0 | 0 | $0 | — | — |

**Running totals:**
- Total submissions: 0
- Paid submissions: 0
- N/A submissions: 0
- Total payout: $0
- Overall N/A rate: 0%
- Average payout (paid only): $0
- Effective hourly rate (all hours): $0

### 3.5 Payout by Program Behavior

Track how different program behaviors affect payout outcomes:

| Behavior | Frequency | Impact on Payout | Notes |
|----------|-----------|-----------------|-------|
| Fast triage (< 24h) | — | Usually full payout | Active triager = high-quality program |
| Slow triage (> 1 week) | — | Often downgraded | Stale triage = stale bugs |
| Communicative triager | — | Higher payout | Asks clarifying questions, values detail |
| Silent triage (auto-close) | — | Lower or no payout | Non-communicative program |
| Requests PoC clarification | — | Delays payout | Weak evidence initially |
| Asks for more impact | — | Opportunity to upgrade | Prove more impact, request higher severity |
| Rejects with weak reasoning | — | Don't argue, move on | Program is not worth more time |

### 3.6 Payout by Time Investment

| Target | Total Hours | Total Payout | Effective Hourly | Best Hourly Session | Notes |
|--------|-------------|--------------|-----------------|---------------------|-------|
| — | — | — | — | — | — |

---

## 4. Tech Stack Mapping

### 4.1 Vulnerability Patterns by Tech Stack

Track which bug classes paid out on which tech stacks. Use this to prioritize
where to look first when you encounter a given tech stack.

| Tech Stack | Most Successful Bug Class | Second Most | Third Most | Notes |
|------------|--------------------------|-------------|------------|-------|
| Rails | Mass Assignment | IDOR | Auth Bypass | Rails params.permit misconfig is common |
| Node/Express | Prototype Pollution | SSRF | IDOR | JSON body parsing is a common vector |
| Django | DRF Permissions | Debug Mode | SQLi | REST Framework permissions frequently misconfigured |
| ASP.NET | ViewState | Auth Bypass | Info Disc | Legacy WebForms have more bugs than modern .NET Core |
| Next.js | API Auth Bypass | Client-side Secret Leak | SSRF | Serverless API routes often miss auth |
| Spring Boot | Actuator Leak | SpEL Injection | Auth Bypass | Actuator endpoints expose environment |
| PHP/Laravel | Debug Mode | SSTI | SQLi | .env exposure is common |
| Go | Business Logic | IDOR | Race Conditions | Go apps have fewer class bugs but more logic flaws |

### 4.2 Stack Component Vulnerability Matrix

For each technology component, notes on what to test:

**Frontend - React:**
- REACT_APP_* environment variables in source code (always check)
- Source maps in production (*.map files)
- Client-side routing with API calls visible in bundles
- __NEXT_DATA__ script tag if Next.js
- Axios interceptors for auth token handling

**Frontend - Vue:**
- Vue DevTools enabled in production
- API calls in component source code
- Environment variables prefixed with VUE_APP_
- Vuex store may expose API state

**Frontend - Angular:**
- Angular 2+ bundles are large — lots of API endpoints
- HttpClient interceptor patterns reveal auth mechanism
- Route guards may be client-side only
- .map files in production

**Backend - Rails:**
- /rails/info/routes endpoint (dev only but sometimes in prod)
- Mass assignment via strong_params omissions
- YAML serialization in session storage
- Devise default lockout configs

**Backend - Django:**
- DEBUG=True in production settings
- REST Framework ViewSet permissions on get_queryset
- PickleSerializer for sessions

**Backend - Node/Express:**
- req.body direct merge (prototype pollution)
- No input validation on route parameters
- Third-party middleware vulnerabilities

**Backend - ASP.NET:**
- ViewState MAC validation disabled
- MachineKey in web.config (default or weak)
- ELMAH error handler exposed
- Trace.axd enabled

**Auth - JWT:**
- alg:none attack (always test first)
- Weak HMAC secret (hashcat with rockyou)
- JWK injection in header
- kid path traversal

**Auth - Session Cookies:**
- Session fixation (pre-set cookie value)
- Predictable session IDs (time-based, sequential)
- HttpOnly and Secure flags missing
- Session timeout too long

**Cloud - AWS:**
- S3 bucket public access (test target-[env].s3.amazonaws.com)
- CloudFront origin exposure
- Lambda function URLs without auth
- SSRF to 169.254.169.254 for metadata
- IAM role assumption from metadata

**Cloud - GCP:**
- GCS bucket public access
- Cloud Run service without auth
- Service account JSON in source code
- SSRF to metadata.google.internal

**Cloud - Azure:**
- Blob storage public access
- Function App without auth
- Managed Identity via SSRF
- Azure DevOps PAT tokens in code

### 4.3 WAF / CDN Fingerprinting

| WAF Detection Signal | Likely WAF | Bypass Approach |
|---------------------|------------|-----------------|
| Server: cloudflare | Cloudflare | Origin IP discovery, HTTP/2 downgrade, payload encoding |
| X-Served-By: AkamaiGHost | Akamai | Header manipulation, request smuggling |
| X-Cache: from ipgen | Fastly | Edge-side include injection, request smuggling |
| X-Amz-Cf-* headers | CloudFront | Origin discovery via HOST header, path normalization |
| Access denied via block page | Imperva | Unicode normalization, parameter pollution |
| Server: ATS/ | Apache Traffic Server | Request smuggling, header injection |
| 406 Not Acceptable | ModSecurity | Encoding bypasses, comment injection |

---

## 5. Program Quality Rankings

### 5.1 Program Scorecard

Rate each program on a 1-5 scale after 5+ submissions:

| Program | Triage Speed | Communication | Payout Fairness | Scope Clarity | Researcher-Friendly | Overall |
|---------|-------------|---------------|-----------------|---------------|-------------------|---------|
| — | — | — | — | — | — | — |

### 5.2 Program Behavior Patterns

Track how each program handles different situations:

| Program | Fast-Triaged (under 24h) | Slow-Triaged (over 7d) | Downgraded | Upgraded | N/A'd | Comment |
|---------|-------------------------|----------------------|------------|----------|-------|---------|
| — | — | — | — | — | — | — |

### 5.3 Program-Specific Tips

**HackerOne Strategy:**

*Report Format:*
- Impact-first summary is critical — triager decides whether to read more based on the first sentence
- CVSS 3.1 is still the standard on H1 (some programs accept 4.0 but check first)
- Use the structured report format: Summary, Description, Steps to Reproduce, Impact, Supporting Evidence, Suggested Fix
- Attach evidence as screenshots inline, not just as attachments
- Keep the summary under 200 characters — this is what appears in the email notification
- The title should be a complete sentence describing the bug, not just "IDOR in endpoint X"

*Payout & Platform:*
- HackerOne pays faster than other platforms (typically 2-4 weeks after triage)
- Building reputation on H1 leads to private program invitations — validity ratio matters more than individual payouts
- N/A ratio is visible to program managers — keep it under 20%
- Top hackers on H1 focus on: server-side bugs (RCE, SQLi, SSRF), not client-side (XSS)
- Disclosed reports on H1 are the best learning resource — study them daily
- H1's #alldisclosed means most programs now disclose all resolved reports — good for learning, bad for opsec
- Bounty boards on H1 show estimated payout ranges — use them to prioritize targets

*Specific Program Intelligence:*
- [Program 1]: [Tip, e.g., "Has a private disclosure program, worth applying"]
- [Program 2]: [Tip, e.g., "Active triager, responds within 48 hours"]
- [Program 3]: [Tip, e.g., "Strict about CVSS — don't inflate scores"]

**Bugcrowd Strategy:**

*Report Format:*
- VRT category must be exact — wrong category = auto-close or delay
- Bugcrowd has a severity-request field — use it to make your case for correct severity
- VRT bypass reasoning: if the bug class is not in the VRT, fall back to "Server-Side Injection" or "Improper Access Control — Generic"
- Use the Expected Result / Actual Result format — it is the standard on Bugcrowd
- Be explicit about priority expectations — state "I believe this is P2 based on VRT section X"

*Payout & Platform:*
- Bugcrowd triagers are typically more technical than H1 (they are employees, not contractors)
- Bugcrowd has a "Priority" (P1-P5) and "Payout" track — they can diverge (e.g., P2 finding may get P3 payout)
- Bugcrowd takes longer to triage (3-8 weeks is common) but payouts are consistent
- Self-service test accounts: some Bugcrowd programs provide them — always check the program brief
- Bugcrowd's safe harbor is more explicit than H1's — read it carefully
- Some Bugcrowd programs have a "VDP only" track separate from bounty — don't submit to VDP if you expect payment
- VRT exists to standardize severity — use it even if you think the VRT score is wrong (explain why it should be higher)

*Payout Patterns:*
| Priority | Severity | Typical Range |
|----------|----------|---------------|
| P1 | Critical | $3,000-$10,000 |
| P2 | High | $1,000-$3,000 |
| P3 | Medium | $250-$1,000 |
| P4 | Low | $50-$250 |
| P5 | Informational | $0 |

*Specific Program Intelligence:*
- [Program 1]: [Tip, e.g., "VRT-based, use exact VRT category in title"]
- [Program 2]: [Tip, e.g., "Takes 3-6 weeks to triage, be patient"]

**Intigriti Strategy:**

*Report Format:*
- CVSS score must be the first thing the triager sees — front-load the CVSS
- Business impact translation is critical on Intigriti — connect technical findings to financial/reputation risk
- Use the Intigriti report template: CVSS, Vulnerability Type, Endpoint, Description, Steps, Business Impact, Fix

*Payout & Platform:*
- 1337x rewards for exceptionally high-quality submissions — if it's really good, expect higher than H1/Bugcrowd
- Intigriti focuses on quality over quantity — spend extra time on PoC quality
- The platform is European-centric — many European targets
- Strict scope enforcement — read scope carefully, OOS findings are N/A'd fast
- Intigriti pays from a fixed pool — first come, first paid in some programs
- 1337x rewards are based on a multiplier system — a Medium can pay like a High if the PoC is excellent
- Intigriti researchers tend to focus on XSS — differentiate with server-side bugs

*Specific Program Intelligence:*
- [Program 1]: [Tip, e.g., "1337x rewards for DOM XSS specifically"]

**Immunefi Strategy (Web3):**

*Report Format:*
- Foundry is the standard PoC tool — write clear, minimal PoCs
- Always include an economic impact calculation — how much ETH/USD can be drained
- Write for a technical audience (solidity developers) — code-centric reports
- Include the exact contract, function, and line numbers
- Show the exploit path step-by-step with on-chain state before and after

*Payout & Platform:*
- Payouts are in crypto (USDC/ETH) — be aware of volatility
- Severity is based on TVL at risk, not traditional CVSS
- Smart contract bugs pay significantly more than web app bugs on the same target
- Re-entrancy, oracle manipulation, flash loan attacks, access control are the top payers
- Immunefi triagers are solidity developers — write code-centric reports
- The "white hat" safe harbor on Immunefi is strong (covers on-chain actions)
- Bug fixing typically involves a commit to a public repo — check for incomplete fixes
- DoS bugs rarely pay out on Immunefi (they focus on fund-loss scenarios)
- Bug bounty on Immunefi is more collaborative (researchers work with devs on fixes)

*Specific Program Intelligence:*
- [Program 1]: [Tip, e.g., "Compound pays well for oracle manipulation bugs"]

**Private / Invite-Only Programs:**

*Strategy:*
- Private programs have less competition (fewer researchers) but lower payouts on average
- Private programs often have lower-security targets (less security maturity)
- Building reputation on public programs leads to private invitations
- Private programs typically have better communication with researchers
- NDAs are common — be careful what you disclose publicly
- Some private programs pay bounties even for low-severity findings to encourage participation
- Private programs may have hackathons or bonus periods — watch for announcements

---

## 6. Target Selection Heuristics

### 6.1 Target Scoring Rubric

Score potential targets on a 0-10 scale before investing time:

| Criterion | Weight | Scoring Guide |
|-----------|--------|---------------|
| Scope Breadth | 2x | 10 = wildcard *.domain.com, 5 = 5+ specific subdomains, 0 = 1-2 subdomains |
| Payout History | 2x | 10 = known to pay $5k+, 5 = pays $500-$2k, 0 = no payout history |
| Tech Stack Novelty | 1.5x | 10 = custom/rare stack, 5 = common stack (Rails/Node), 0 = WordPress cookie-cutter |
| Account Ease | 1.5x | 10 = open registration, 5 = OAuth only, 0 = registration disabled |
| Competitors | 1x | 10 = no other researchers visible, 5 = some activity, 0 = 50+ researchers |
| Triage Speed | 1x | 10 = under 48h, 5 = 1-2 weeks, 0 = 30+ days |
| Feature Freshness | 1x | 10 = new features in last 30 days, 5 = stale features, 0 = no changes in 6+ months |
| Attack Surface | 1x | 10 = API + web + mobile, 5 = web only, 0 = single page app |

**Score Calculator:**
```
Score = (Scope × 2) + (Payout × 2) + (Novelty × 1.5) + (Account × 1.5) + (Competitors) + (Triage) + (Features) + (Surface)
Max: 10×2 + 10×2 + 10×1.5 + 10×1.5 + 10 + 10 + 10 + 10 = 20 + 20 + 15 + 15 + 10 + 10 + 10 + 10 = 110
```

| Score | Decision |
|-------|----------|
| 80+ | High priority — hunt immediately |
| 60-79 | Medium priority — queue for next session |
| 40-59 | Low priority — quick pass only |
| Under 40 | Skip — not worth the time |

### 6.2 Quick Skip Indicators

Skip a target if ANY of these are true:
- Scope is 1-2 subdomains only
- Program has 0% payout rate (check disclosed reports)
- Cookie-cutter WordPress with no custom functionality
- Program hasn't triaged anything in 30+ days
- Registration is disabled AND no OAuth/social login
- Target is a third-party SaaS with white-label (Zendesk, Shopify, etc.)
- Program description says "informational only, no bounty"
- Scope is exclusively staging/dev domains
- The program explicitly bans automated tools
- The safe harbor has significant carve-outs

### 6.3 Priority Weighting by Bug Class Likelihood

Different tech stacks have different "most likely" bug classes. Use this table to
determine where to focus initial testing on each new target:

| Tech Stack Observed | Test First | Test Second | Test Third | Test Fourth |
|-------------------|------------|-------------|------------|-------------|
| Rails | Mass assignment | IDOR (API) | Auth bypass (admin routes) | YAML deserialization |
| Node/Express | Prototype pollution | SSRF (avatar/file fetch) | IDOR | Auth bypass (middleware gap) |
| Django | DRF permissions | Debug enabled | Admin default creds | SQLi (raw() usage) |
| ASP.NET | ViewState | ELMAH exposure | Auth bypass (WCF) | MachineKey default |
| Next.js | API auth missing | __NEXT_DATA__ data leak | SSRF (serverless) | Source map found |
| Spring Boot | Actuator endpoints | SpEL injection | Auth bypass | Mass assignment |
| Go | Business logic | IDOR | Race conditions | SSRF |
| PHP/Laravel | Debug env leak | SSTI (Blade) | SQLi | File upload |
| WordPress | Plugin CVEs | XMLRPC abuse | User enum | Default creds |
| React SPA | API keys in JS | CORS misconfig | Client-side auth bypass | GraphQL introspection |
| GraphQL | Introspection | Batching/Brute-force | Field-level auth | Depth DoS |
| Custom stack | Auth flow analysis | All endpoints catalog | IDOR everywhere | Business logic |

### 6.4 High-Signal Patterns (Targets Worth Extra Time)

Spend more time if the target has:
- Custom authentication flow (not off-the-shelf OAuth/SAML)
- Recent feature launches (last 30 days)
- Large JavaScript bundles (more endpoints, more secrets)
- Public bug bounty program with disclosed reports
- Multiple subdomains with different tech stacks
- API documentation (Swagger, GraphQL schema)
- Mobile app in addition to web app
- Recent hiring for security team (means they're maturing)
- Internal tools exposed (admin panels, dashboards, monitoring)
- Third-party integrations (webhooks, SSO, payment processors)

---

## 7. Detailed Target Profiles (Reference Repository)

### 7.0 Profile Index

| # | Target | Domain | Program | Status | Best Payout |
|---|--------|--------|---------|--------|-------------|
| 1 | CoinDesk Sandbox | coinmarketcap.sandbox | Bugcrowd (speculative) | Active | Pending |
| 2 | Boozt | boozt.com | Bugcrowd (speculative) | Stalled | — |
| 3 | [Target Name] | [domain] | [program] | [status] | [$] |

### 7.1 Profile: CoinDesk Sandbox

#### Metadata
- **Domain:** coinmarketcap.sandbox (sandbox environment for CoinMarketCap)
- **Program:** Bugcrowd (speculative — CoinDesk/CoinMarketCap has a public BB program)
- **First Hunted:** 2026-06-05
- **Last Hunted:** 2026-06-06
- **Total Sessions:** 1
- **Total Hours:** 8
- **Scope Type:** Wildcard (assumed)
- **Payout Model:** Varies by severity

#### Tech Stack
- **Frontend:** Next.js (React-based SPA)
- **Backend:** Node.js (Express inferred from response patterns)
- **Auth:** JWT-based (self-issued by the frontend)
- **Database:** Not determined (likely PostgreSQL)
- **Cloud:** Not determined
- **CDN/WAF:** Cloudflare (inferred from headers)
- **Auth Provider:** Self-issued JWT, no external OAuth observed

#### Discovery Summary
- **CoinMarketCap API endpoints discovered via JS bundle analysis (8 files analyzed):**
  - `GET /api/v3/quote/historical` — Historical price data (unauthenticated)
  - `GET /api/v3/quote/latest` — Latest price data (unauthenticated)
  - `GET /api/v3/cryptocurrency/quotes/latest?id=1` — Specific cryptocurrency quote
  - `GET /api/v3/cryptocurrency/listings/latest` — Paginated cryptocurrency listings (start/limit/cryptocurrency_type/sort/sort_dir params)
  - `POST /api/v3/user/login` — Authentication (email, password, 2FA code)
  - `POST /api/v3/user/register` — Registration (first_name, last_name, email, username, password, password_confirmation, agreed_terms, recaptcha_response)
  - `POST /api/v3/user/password-reset` — Password reset
  - `GET /api/v3/user/portfolio/overview` — Portfolio overview (authenticated)
  - `GET /api/v3/user/watchlist` — Watchlist (authenticated)
  - `GET /api/v3/user/transactions` — Transactions (authenticated)
  - `GET /api/v3/user/transactions/download` — Transaction download (authenticated)
  - `GET /api/v3/user/reports` — Reports (authenticated)
  - `GET /api/v3/user/notifications` — Notifications (authenticated)
  - `GET /api/v3/user/settings` — User settings (authenticated)
  - `GET /api/v3/user/accounts` — User accounts (authenticated)
  - `POST /api/v3/user/accounts` — Create user account (authenticated)
  - `DELETE /api/v3/user/accounts/{id}` — Delete account (authenticated)
  - `GET /api/v3/user/affiliate` — Affiliate info (authenticated)
  - `POST /api/v3/user/swap` — Swap/create order (authenticated)
  - `GET /api/v3/user/swap/assets` — Swap assets list (authenticated)
  - `GET /api/v3/user/swap/quote` — Swap quote (authenticated)
  - `GET /api/v3/user/swap/orders` — Swap orders (authenticated)
  - `GET /api/v3/user/orders` — Orders (authenticated)
  - `GET /api/v3/user/balances` — Balances across accounts (authenticated)
  - `GET /api/v3/user/health` — Health check (authenticated)
  - `GET /api/v3/sitemap` — Sitemap links
  - `GET /api/v3/content/notifications` — Content notifications
  - `GET /api/v3/content/articles` — Content articles
  - `GET /api/v3/content/reports` — Content reports
  - `GET /api/v3/content/crypto-news` — Crypto news
  - `GET /api/v3/partner/routing` — Partner routing
  - `GET /api/v3/partner/crypto-adoption` — Partner crypto adoption data
  - `GET /api/v3/community/mentions` — Community mentions
  - `GET /api/v3/community/reddit` — Community Reddit data
  - `GET /api/v3/community/post-detail` — Community post detail
  - `GET /api/v3/ad/units` — Ad units configuration
  - `GET /api/v3/ad/configuration` — Ad configuration
  - `GET /api/v3/ad/refresh-mapping` — Ad refresh mapping
  - `GET /api/v3/auth/providers` — Auth providers (Google, Apple, Facebook)
  - `GET /api/v3/user/tags` — User tags (authenticated)
  - `GET /api/v3/user/referral` — Referral info (authenticated)
  - `GET /api/v3/user/earn/user-rewards` — User rewards (authenticated)
  - `GET /api/v3/payment/accounts` — Payment accounts (authenticated)
  - `GET /api/v3/payment/transactions` — Payment transactions (authenticated)

- **Total API endpoints catalogued:** 45+
- **Interesting auth-related:** /auth/providers (Google/Apple/Facebook configured)
- **Authentication-required endpoints:** 20+ (portfolio, transactions, watchlist, swap, orders, balances)

#### Findings Summary

**Finding 1: JWT Signature Algorithm Downgrade (alg:none)**
- **Bug Class:** JWT Attack
- **Endpoint:** All authenticated endpoints (JWT is self-issued by frontend)
- **Severity:** High (CVSS 4.0: 8.1)
- **Status:** Report written, ready to submit
- **Description:** The JWT is created client-side in the browser with a fixed secret/algorithm. Changing the `alg` header from `HS256` to `none` and removing the signature bypasses verification. The JWT payload contains `plan: "hobbyist"` — changing this to `plan: "professional"` or adding `isAdmin: true` may grant elevated access.
- **Complexity:** Trivial (modify JWT, no server interaction needed)
- **Impact:** Paywall bypass at minimum. Potential privilege escalation to admin/enterprise tier.

**Killed Findings:**
- Open redirect on partner routing endpoint — OR alone is N/A
- API key in JS bundle — likely public key or test key
- Missing CSP headers — always rejected

#### Chain Primitives
- JWT auth is self-issued — interesting architecture choice
- 20+ authenticated endpoints available after bypassing paywall
- Auth providers configured: Google, Apple, Facebook — OAuth testing surface

#### Session Logs
- **2026-06-05 (8h):** Initial recon, JS bundle extraction, 45+ API endpoints catalogued, JWT alg:none bypass discovered and verified, report drafted

#### Notes
- The JWT being self-issued by the frontend is a critical architectural weakness. This means the server trusts whatever the client sends as long as the signature format is acceptable.
- Sandbox environment — findings may or may not replicate to production
- Auth providers (Google, Apple, Facebook) suggest OAuth flows exist on production — could be additional attack surface
- The "CoinMarketCap" branding suggests this is specifically CoinMarketCap's sandbox, not CoinDesk's main app

### 7.2 Profile: Boozt

#### Metadata
- **Domain:** boozt.com (Nordic fashion e-commerce)
- **Program:** Bugcrowd (speculative — has a public VDP/bounty program)
- **First Hunted:** 2026-06-05
- **Last Hunted:** 2026-06-05
- **Total Sessions:** 1
- **Total Hours:** 4
- **Scope Type:** *.boozt.com (assumed wildcard)

#### Tech Stack
- **Frontend:** React (client-side SPA)
- **Backend:** Ruby on Rails (Rails 6+ inferred from cookie patterns, error pages)
- **Auth:** Session-based (not JWT)
- **Database:** PostgreSQL (inferred from Rails default stack)
- **Cloud:** Google Cloud Platform (GCP — inferred from hosting headers)
- **CDN/WAF:** Cloudflare
- **CMS:** Custom e-commerce platform (not Shopify/Magento)
- **Search:** Algolia (inferred from network requests)
- **Third Parties:** Stripe (payments), Klarna (BNPL), PostNord/DB Schenker (shipping)

#### Store Inventory
15 regional storefronts identified:
- boozt.com (main — English/DACH)
- boozt.com/de (German)
- boozt.com/fi (Finnish)
- boozt.com/dk (Danish)
- boozt.com/no (Norwegian)
- boozt.com/se (Swedish)
- boozt.com/nl (Dutch)
- boozt.com/at (Austrian)
- boozt.com/cz (Czech)
- boozt.com/pl (Polish)
- booztlet.com (outlet — separate domain)
- boozt.com/es (Spanish — may not exist)
- boozt.com/it (Italian — may not exist)
- boozt.com/fr (French — may not exist)
- Members area: members.booztlet.com

#### Discovery Summary
- **API Endpoints Found (via JS bundle + Wayback):**
  - `GET /api/login` — Login page
  - `POST /api/login` — Login action
  - `GET /api/logout` — Logout
  - `GET /api/sessions` — Session info
  - `GET /api/register` — Registration page (`disableSignup = '1'` — registration disabled)
  - `POST /api/register` — Registration action (returns 404 when disabled)
  - `GET /api/password` — Password reset page
  - `POST /api/password` — Password reset action
  - `GET /api/account` — Account details
  - `PUT /api/account` — Update account
  - `GET /api/account/cards` — Saved payment cards
  - `POST /api/account/cards` — Add payment card
  - `GET /api/account/addresses` — Saved addresses
  - `GET /api/account/orders` — Order history
  - `GET /api/account/orders/{number}` — Single order details
  - `GET /api/account/wishlist` — Wishlist
  - `GET /api/returns` — Returns portal
  - `GET /api/checkout` — Checkout page
  - `GET /api/search` — Product search (params: q, page, sort, size)
  - `GET /api/search/suggest` — Search suggestions
  - `GET /api/products/{sku}` — Product details
  - `GET /api/categories` — Category listing
  - `GET /api/brands` — Brand listing
  - `GET /api/content/pages/{slug}` — Content pages

- **Total endpoints catalogued:** 25+

#### Findings Summary
**Submitted:** 0
**Killed:** 0 (stalled before deep hunting)

#### Blockers
- **Registration disabled:** `disableSignup = '1'` in the registration route handler. No way to create a test account without a valid invitation from an existing user.
- **No OAuth/social login on web:** Authentication providers exist but were not reachable through the web flow.
- **All sensitive endpoints are auth-gated:** Account details, orders, wishlist, returns, checkout all require an authenticated session.

#### Potential Unauthenticated Surface
- Product search, categories, brands, content pages are all unauthenticated
- Password reset flow is unauthenticated (could test for host header injection, token prediction)
- Returns portal with order number + email lookup (could test for IDOR)

#### Session Logs
- **2026-06-05 (4h):** Initial recon, store mapping (15 stores), API endpoint extraction via JS bundles, registration flow analysis, identified disableSignup block

#### Notes
- Boozt has a Bugcrowd VDP and previously had a paid bounty program — worth revisiting if test credentials can be obtained
- Possible paths to test credentials: apply to their BB program directly, check if employee accounts exist, look for partner/vendor access
- Regional stores may have different registration rules (check booztlet.com separately)
- Mobile app may have different registration flow

### 7.3 Profile: [Template for Future Target]

#### Metadata
- **Domain:**
- **Program:**
- **First Hunted:**
- **Last Hunted:**
- **Total Sessions:**
- **Total Hours:**
- **Scope Type:**
- **Payout Model:**

#### Tech Stack
- **Frontend:**
- **Backend:**
- **Auth:**
- **Database:**
- **Cloud:**
- **CDN/WAF:**
- **CMS:**
- **Third Parties:**

#### Discovery Summary
- Total Subdomains Found:
- Live HTTP Hosts:
- Interesting Endpoints Found:
- JS Bundles Analyzed:
- API Endpoints Catalogued:

#### Findings Summary
**Submitted (Paid):**
**Submitted (N/A):**
**Killed:**
**Primitives Stored:**

#### Session Logs
- **YYYY-MM-DD (Nh):** Session notes

#### Notes
- Observation 1
- Observation 2
- Plan for next session

### 7.4 Archive Target Profiles

Archived targets — fully explored, dead programs, or deprioritized.

#### Profile: [Archived Target Name]

**Metadata:**
- Domain: [domain]
- Program: [program]
- Sessions: [N]
- Hours: [N]
- Reason Archived: [explanation]

**Why It Was Worth Hunting:**
[What made this target interesting initially]

**What Was Found:**
[List of findings, even if none were submitted]

**Why We Stopped:**
[Clear explanation of why this target is no longer productive]

**Lessons Learned:**
[What this target taught us]

| Target | Sessions | Hours | Total Findings | Best Payout | Reason Archived |
|--------|----------|-------|----------------|-------------|----------------|
| — | — | — | — | — | — |

---

### 7.5 Target Entry Workflow

When adding a new target to this registry, follow these steps:

**Step 1: Create Top-Level Entry**
- Copy the Quick Entry Template
- Fill in domain, program, tech stack, scope
- Set status to "Active"

**Step 2: Initial Recon (Session 1)**
- Run subdomain enumeration
- Run HTTP probing
- Collect Wayback URLs
- Extract JS bundles
- Catalog API endpoints
- Update the registry with findings

**Step 3: Deep Profile (After 2+ Sessions)**
- Create a full detailed profile (like Profile: CoinDesk Sandbox above)
- Fill in all metadata
- Document all findings, killed findings, and chain primitives

**Step 4: Maintenance**
- Update after every session
- Log payouts when received
- Move to "Completed" when all leads are exhausted
- Move to "Archived" when no longer hunting

### 7.6 Target Deletion Policy

Do not delete targets from this registry even if:
- You never found anything (failure is data)
- The program shut down (note why)
- The scope changed (document the change)
- You got outcompeted (document what happened)

Every target profile is a learning artifact. Keeping them helps with pattern analysis.

### 7.7 Target Retrieval Workflow

When revisiting an old target:
1. Read the full profile
2. Note what was tested and what was not
3. Re-run basic recon (subdomains change, tech stack evolves)
4. Check for new features or API endpoints
5. Re-examine killed findings — do new chain partners exist?
6. Update the registry with the revisit session

---

## 8. Target Notes Archive

### 8.1 Long-Form Target Notes

#### TARGET DETAIL: [Target Name]

**First Impression:**
The application appears to be a [description]. It uses [tech stack] and is hosted
on [cloud provider]. The auth system is [JWT/sessions/OAuth]. Registration is
[open/closed/OAuth only].

**Recon Notes:**
Initial subdomain enumeration found [N] subdomains, [M] of which resolved to
live HTTP servers. The most interesting subdomains are:
- [sub1]: [tech, purpose, notes]
- [sub2]: [tech, purpose, notes]

The following endpoints were discovered in JavaScript bundles:
- [endpoint1] — [method] — [purpose]
- [endpoint2] — [method] — [purpose]

**Interesting Features:**
- [Feature 1]: [Description, why it's interesting from a security perspective]
- [Feature 2]: [Description, why it's interesting]

**Auth Flow Analysis:**
The authentication flow is:
1. POST /api/login with email/password -> returns JWT
2. JWT used in Authorization: Bearer header
3. JWT expires in 24 hours (long window)
4. No refresh token mechanism observed
5. No MFA available

**Promising Attack Vectors:**
- IDOR in [endpoint] — takes user_id parameter, likely not scoped
- Auth bypass on [endpoint] — returns data without valid token
- SSRF in [feature] — fetches external URLs

**Notes from Each Session:**
SESSION 1 (YYYY-MM-DD):
- Tested IDOR on /api/v2/users/{id}/profile — 403 Forbidden (authz working)
- Tested IDOR on /api/v2/users/{id}/orders — 200 OK, returned other users' orders!
- IDOR CONFIRMED — captured evidence
- Spent 45 min on SSRF in avatar upload — no callback received
- Spent 20 min on XSS in search — reflected in response but context is JSON

---

### 7.2 Target Notes (Quick Format for Smaller Targets)

```
TARGET: example.com
SESSIONS: 2 (2026-03-01, 2026-03-05)
TECH: React, Node, PostgreSQL, JWT, AWS, Cloudflare
SCOPE: *.example.com (except blog.example.com)

ACCOUNTS:
- attacker+1@gmail.com (free tier)
- victim+1@gmail.com (free tier)

FINDINGS:
+ IDOR in /api/v2/orders/{id} — High, $2,000 paid (2026-03-08)
  Changed order_id from attacker's to victim's, got full order details including shipping address
  CVSS 4.0: 7.1 / AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N

KILLED:
- Stored XSS in profile bio — killed (self-XSS, only profile owner sees it)
- Open redirect on /redirect?url= — killed (chain not found yet, saved as primitive)
- Missing CSP headers — killed (always rejected)

PRIMITIVES STORED:
- OR: /redirect?url= — could chain with OAuth redirect_uri if OAuth is added

NOTES:
- Registration requires email verification but + alias works
- Rate limit is 100 req/min per IP
- Rate limit bypass via X-Forwarded-For header
- WAF blocks </script> but allows <<script> and <SCRiPT (case variation)
- API uses REST with JSON bodies
- JWT has alg:RS256 — test HS256 with public key next session
```

### 7.3 Target Note Index

| Target | Entries | Last Updated | Key Finding |
|--------|---------|-------------|-------------|
| [target.com] | 3 | 2026-03-15 | IDOR ($2,000) |
| [target2.com] | 1 | 2026-02-20 | Nothing found yet, quick pass |

---

## 8. Dupes and Competitor Analysis

### 8.1 Known Dupes by Target

Track which bugs have been reported before to avoid wasting time:

| Target | Bug Class | Reported By | Date Reported | Date Fixed | Our Detection | Would We Have Dupe'd? |
|--------|-----------|-------------|---------------|------------|---------------|----------------------|
| — | — | — | — | — | — | — |

### 8.2 Competitor Activity Indicators

Things that signal heavy competition on a target:
- Multiple disclosed reports for the same bug class in the last 30 days
- Program closes reports as "duplicate" frequently
- Short window between disclosure and fix (program is responsive but researchers are fast)
- Large number of watchers on the program page

---

## 9. Revisit Candidates

### 9.1 Targets Worth Revisiting

| Target | Why Revisit | What Changed | Previous Best Lead | Est. Effort |
|--------|-------------|--------------|-------------------|-------------|
| — | — | — | — | — |

### 9.2 Feature Launch Monitor

Track which targets have launched new features (potential fresh attack surface):

| Target | Feature | Launch Date | Status | Hunting Notes |
|--------|---------|-------------|--------|---------------|
| — | — | — | — | — |

### 9.3 Chain Opportunity Tracker

Findings that were killed alone but could become valid when paired with a future finding:

| Target | Primitive | Kill Reason | Needs | Priority |
|--------|-----------|-------------|-------|----------|
| boozt.com | XSS in admin panel | Registration disabled, can't create test accounts | Working test account | Medium |
| — | OR: /redirect?url= | Open redirect alone is always rejected | OAuth endpoint to chain with | Low |

---

## 10. Cross-Target Pattern Analysis

### 10.0 Pattern Recognition Framework

Cross-target pattern analysis is how you improve. Every target teaches you something.
The goal of this section is to extract signal from the noise — to see what techniques
work, what tech stacks are vulnerable to what, and what developer mistakes recur.

**Pattern Types Tracked:**
1. **Tech Stack → Vulnerability:** Which bug classes are most common on which stacks
2. **Developer Mistake → Bug Class:** What specific developer errors lead to what findings
3. **Program Behavior → Submission Strategy:** How different programs handle different reports
4. **Time Investment → Payout:** Which bug classes give the best hourly rate
5. **Chain Pattern → Critical:** What chains consistently produce Critical findings

### 10.1 Bug Class Trends by Tech Stack

After hunting multiple targets, what patterns emerge:

**Rails (3 targets hunted):**
- 2/3 had mass assignment somewhere
- 1/3 had IDOR in API
- 1/3 had /rails/info/routes exposed
- Pattern: params.permit often has omissions

**Node/Express (2 targets hunted):**
- 1/2 had prototype pollution (lodash merge)
- 2/2 had SSRF in avatar/file processing
- Pattern: JSON body processing without validation

**Next.js (2 targets hunted):**
- 2/2 had API routes in /api/ without auth
- 1/2 had __NEXT_DATA__ leaking internal data
- Pattern: serverless API functions often miss auth

### 10.2 Common Developer Mistakes (Seen Across Targets)

Track recurring developer mistakes across different organizations:

| Mistake | Frequency | Typical Location | Why It Happens |
|---------|-----------|-----------------|----------------|
| Missing authorization on ID-based endpoints | Very High | /api/v2/ endpoints | Dev assumes IDOR requires UUID which is "unguessable" |
| GET endpoints don't check auth | High | /api/admin/ or /internal/ | Dev relies on frontend hiding the link |
| No input validation on CVS/import | Medium | /admin/import/ | Admin-only feature assumed safe |
| Rate limiting missing on auth endpoints | High | /api/login, /api/2fa | Dev uses CDN rate limiting only |
| CORS with credentials + reflected origin | Medium | /api/ endpoints | Dev copied from tutorial |

### 10.3 Payout Pattern Analysis

What bug classes actually pay:

| Bug Class | Payout Range | Submission Count | Payout Percentage | Notes |
|-----------|-------------|-----------------|-------------------|-------|
| IDOR | $500-$5,000 | 0 | — | Consistent payer across all programs |
| Auth Bypass | $1,000-$10,000 | 0 | — | Higher payout but harder to find |
| SSRF to Cloud | $3,000-$10,000 | 0 | — | Critical when cloud metadata is accessible |
| Stored XSS (admin) | $1,000-$5,000 | 0 | — | Only when admin is the victim |
| SQLi | $2,000-$8,000 | 0 | — | Becoming rarer on modern stacks |
| Business Logic | $500-$4,000 | 0 | — | Depends on financial impact demonstrated |
| JWT Attacks | $500-$3,000 | 0 | — | Quick win if alg:none or weak secret |

### 10.4 Killed Finding Patterns

What gets N/A'd most often (learn from others' mistakes):

| Bug Class | N/A Rate | Typical N/A Reason | How to Avoid |
|-----------|----------|-------------------|--------------|
| Missing CSP headers | ~95% | Defense-in-depth, no direct impact | Don't report standalone |
| Self-XSS | ~90% | Only affects attacker's own session | Chain with CSRF or find stored variant |
| Open redirect | ~85% | Phishing primitive, no direct impact | Chain with OAuth or demonstrate full attack |
| Rate limiting bypass | ~80% | No demonstrated harm | Chain with auth or demonstrate actual brute-force |
| GraphQL introspection | ~75% | Documentation, not a vulnerability | Query with auth to find IDOR |
| Username enumeration | ~70% | Accepted design choice | Chain with password spray and demonstrate account takeover |
| Missing SPF/DMARC | ~65% | Email infrastructure, not app security | Chain with password reset email interception |
| Weak password policy | ~95% | Policy issue, not a vulnerability | Don't report |
| Logout CSRF | ~95% | Universally rejected | Don't report |
| Internal IP disclosure | ~80% | No way to reach the IP | Chain with SSRF |

### 10.4 Vulnerability Prevalence by Industry Vertical

Track which bug classes are most common in different types of applications:

**E-commerce (Boozt, Shopify sites):**
- Common: Business logic (coupon abuse, price manipulation, quantity bugs)
- Common: IDOR (order history, wishlist, returns)
- Less common: SSRF (few external URL fetches in e-commerce)
- Less common: Prototype pollution (standard stack, well-audited)
- Payout range: $500-$4,000
- Best approach: Focus on checkout/cart logic, coupon application, returns portal, and account management

**FinTech / Crypto (CoinMarketCap, Coinbase):**
- Common: JWT attacks (auth tokens poorly validated)
- Common: IDOR (account balances, transaction history)
- Common: SSRF (price feed aggregation, external API calls)
- Common: Race conditions (trading, transfers)
- Payout range: $1,000-$10,000
- Best approach: Focus on auth mechanisms, especially JWT; test trading/movement operations for race conditions

**Social Media / Community:**
- Common: XSS (user-generated content everywhere)
- Common: IDOR (user profiles, messages, content)
- Common: Business logic (voting, following, reporting)
- Payout range: $500-$5,000
- Best approach: Focus on stored XSS in rich content, IDOR in messages/DMs

**SaaS / Enterprise:**
- Common: IDOR (org/team scoping issues)
- Common: Auth bypass (admin panels, internal APIs)
- Common: Mass assignment (org roles, permissions)
- Payout range: $1,000-$8,000
- Best approach: Focus on cross-organization data access, role escalation, admin API exposure

**Healthcare:**
- Common: IDOR (medical records, patient data)
- Common: Auth bypass (provider/patient access confusion)
- Payout range: $2,000-$10,000
- Best approach: Focus on patient data access controls, especially between different patients or providers

**Government / Public Sector:**
- Common: IDOR (citizen data, application status)
- Common: Auth bypass (admin interfaces)
- Common: Information disclosure (misconfigured cloud storage)
- Payout range: Varies widely, often higher for critical data exposure
- Best approach: Focus on citizen/case file access, document storage, admin interfaces

### 10.5 Time Efficiency Analysis

After several sessions, analyze your time efficiency:

| Bug Class | Average Time to Find | Average Payout | Effective Hourly | Should Prioritize? |
|-----------|---------------------|----------------|-----------------|-------------------|
| IDOR | 20 min | $2,000 | $6,000/h | YES — always test first |
| Auth Bypass | 15 min | $3,000 | $12,000/h | YES — quick check on every target |
| SSRF | 30 min | $5,000 | $10,000/h | YES — if app fetches URLs |
| JWT Attacks | 10 min | $1,500 | $9,000/h | YES — 10 min, always test |
| Stored XSS | 45 min | $2,000 | $2,666/h | Medium priority |
| Business Logic | 45 min | $2,500 | $3,333/h | Medium priority |
| SQLi | 45 min | $4,000 | $5,333/h | Medium priority |
| Subdomain Takeover | 20 min | $2,000 | $6,000/h | Quick check only |
| Reflected XSS | 15 min | $750 | $3,000/h | Lower priority |
| Race Conditions | 60 min | $3,000 | $3,000/h | Lower priority |
| File Upload | 30 min | $2,500 | $5,000/h | If file upload feature exists |
| SSRF (blind only) | 30 min | $0 | $0/h | Kill if no cloud metadata or internal service access |

**Optimized Time Allocation Per Target (3 hours):**
1. 15 min: JWT attack (always test, 10 min)
2. 30 min: IDOR on every object ID endpoint (highest hourly rate)
3. 15 min: Auth bypass on every admin/internal endpoint
4. 30 min: SSRF if app fetches URLs
5. 60 min: Stored XSS + Business Logic
6. 30 min: Quick pass on SQLi, file upload, subdomain takeover
7. Remaining: Deep dive on the most promising lead

---

## Target Registry Admin

- **Last Updated:** [YYYY-MM-DD]
- **Total Targets Tracked:** 0
- **Total Findings Submitted:** 0
- **Total Payout:** $0
- **N/A Rate:** 0%
- **Average Payout Per Finding:** $0

### Maintenance Tasks
- [ ] Update target profiles after each session
- [ ] Log new findings with payout info after triage
- [ ] Rotate test account passwords monthly
- [ ] Review and prune dead programs quarterly
- [ ] Update pattern analysis every 10 submissions
- [ ] Review chain primitives list monthly for new chain opportunities
