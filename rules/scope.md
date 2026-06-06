# Scope Management Rules

> "Scope is the line between a paid bounty and a permanent ban."
> Scope violations are the #1 reason hunters get banned from platforms.

---

## Table of Contents

1. [SCOPE IS THE LAW](#1-scope-is-the-law)
2. [READING PROGRAM SCOPE](#2-reading-program-scope)
3. [WILDCARD SCOPE INTERPRETATION](#3-wildcard-scope-interpretation)
4. [THIRD-PARTY SERVICE DETECTION](#4-third-party-service-detection)
5. [SCOPE VERIFICATION PROTOCOL](#5-scope-verification-protocol)
6. [IP-BASED SCOPE](#6-ip-based-scope)
7. [ACQUIRED COMPANY SCOPE](#7-acquired-company-scope)
8. [EXCLUDED BUG CLASSES](#8-excluded-bug-classes)
9. [EXCLUDED ACTIONS](#9-excluded-actions)
10. [SAFE HARBOR](#10-safe-harbor)
11. [SCOPE FOR MOBILE APPS](#11-scope-for-mobile-apps)
12. [SCOPE FOR API-ONLY PROGRAMS](#12-scope-for-api-only-programs)
13. [SCOPE FOR WEB3/DEFI](#13-scope-for-web3defi)
14. [SCOPE CHANGES](#14-scope-changes)
15. [EDGE CASES](#15-edge-cases)
16. [SCOPE VERIFICATION SCRIPTS](#16-scope-verification-scripts)
17. [DOCUMENTING SCOPE](#17-documenting-scope)
18. [WHAT TO DO WHEN SCOPE IS UNCLEAR](#18-what-to-do-when-scope-is-unclear)
19. [COMMON SCOPE MISTAKES](#19-common-scope-mistakes)
20. [SCOPE FOR BURP/PROXY](#20-scope-for-burpproxy)
21. [SCOPE RECONCILIATION](#21-scope-reconciliation)

---

## 1. SCOPE IS THE LAW

### Why Scope Matters

Bug bounty platforms grant you a limited license to test specific assets. Everything outside that license is unauthorized access. Scope is the contract that separates legal testing from illegal intrusion.

### One OOS Request = Potential Ban

Platforms monitor every request. When you hit an out-of-scope asset:

- HackerOne: Automated alerts trigger on OOS domain access. Manual review can result in a 30-day suspension or permanent ban.
- Bugcrowd: The platform tracks your testing activity. Repeated OOS hits will lock your account.
- Intigriti: Strict scope enforcement. OOS testing is a violation of their code of conduct.
- Immunefi: OOS smart contract interaction can result in immediate removal from all programs.
- Synack: Red teamers testing OOS assets lose their platform access permanently.

### One OOS Report = Instant Close

Submitting a finding on an out-of-scope asset:

- The report is closed within minutes (often automated).
- Your credibility score drops.
- Program trust erodes — triagers remember bad submissions.
- Repeat OOS reports can lead to program-specific bans.

### Legal Consequences

Beyond platform bans:

- Testing outside scoped assets is unauthorized computer access.
- The Computer Fraud and Abuse Act (CFAA) in the US covers OOS testing.
- The Computer Misuse Act in the UK similarly criminalizes unauthorized access.
- Safe harbor clauses explicitly only protect in-scope, good-faith testing.
- Multiple hunters have faced legal action for exceeding scope.

### The Scope Check Habit

Before every single action — every curl, every Burp proxy pass, every script — verify scope.

```
ALWAYS ASK: "Is this asset explicitly or implicitly in scope?"
IF UNCERTAIN: Do not touch it until verified.
IF OOS: Do not touch it at all.
```

### Platform Penalty Tiers

| Offense | HackerOne | Bugcrowd | Intigriti | Immunefi |
|---------|-----------|----------|-----------|----------|
| 1st OOS request | Warning | Warning | Warning | Warning |
| Repeated OOS | 30-day suspension | Account locked | Account frozen | Program ban |
| OOS report | Report closed + warning | Report closed + warning | Report closed + warning | Report closed |
| Malicious OOS | Permanent ban | Permanent ban | Permanent ban | Permanent ban |

### The Career Impact

A ban on one platform often spreads:

- Programs cross-reference banned hunters.
- Platform bans are permanent — you lose access to all programs on that platform.
- HackerOne bans affect all current and future programs.
- Bugcrowd competitive programs check your standing.
- Reputation damage follows you across the industry.

### Scope Discipline == Professionalism

Professional hunters have zero OOS findings. They build scope verification into every workflow. They automate scope checking. They archive scope pages. They treat scope as the foundational document of every engagement.

### The Simple Rule

**If it's not explicitly in scope, it's out of scope.**

Not "probably in scope." Not "it looks like the same company." Not "logically it should be." If the program page doesn't list it, you cannot test it.

### Scope Changes During Engagement

Programs can change scope:

- They may not notify you.
- Always refresh scope before each session.
- Check for program policy updates.
- Scope can shrink without warning.
- Never assume yesterday's scope is today's scope.

---

## 2. READING PROGRAM SCOPE

### The Scope Parsing Methodology

Reading scope is not just glancing at a list of domains. It requires systematic parsing, categorization, and verification.

### Step 1: Read the Program Brief

Every program page has a description area. Read it in full before looking at the scope list. The description often contains:

- What the program cares about most.
- Technologies used (helps scope verification).
- Specific areas of interest.
- Warning about specific out-of-scope items.
- Testing methodology preferences.

### Step 2: Parse the Scope Table

Most platforms present scope in a table format:

```
| Target | Type | In Scope? |
|--------|------|-----------|
| *.example.com | URL | Yes |
| api.example.com | URL | Yes |
| www.example.com | URL | Yes |
| example.com | URL | Yes |
| *.acq-example.com | URL | No |
```

Parse each row individually:

- **Target**: The asset identifier.
- **Type**: URL, CIDR, mobile app, source code, smart contract.
- **In Scope?**: Yes or No.

### Step 3: Categorize Each Entry

For each in-scope entry, categorize:

```
IN-SCOPE CATEGORIES:
  - Wildcard domains (*.example.com)
  - Specific subdomains (admin.example.com)
  - Root domains (example.com)
  - Specific paths (example.com/api/v2)
  - IP ranges (192.168.0.0/24)
  - Mobile apps (Android/iOS package names)
  - Desktop apps (executable names)
  - Source code (GitHub repos)
  - Smart contracts (contract addresses)
  - API endpoints (specific URLs or base paths)
```

### Step 4: Identify Scope Patterns

Common scope patterns:

```
Wildcard pattern:
  *.example.com -> ALL subdomains at any depth

Specific subdomain:
  www.example.com -> ONLY www subdomain
  api.example.com -> ONLY api subdomain

Root domain:
  example.com -> Only the root, no subdomains
  (Actual: most platforms treat this as "*.example.com")

Path-specific:
  example.com/app -> Only /app path and children
  example.com/api -> Only /api path and children
```

### Step 5: Parse Out-of-Scope Entries

OOS entries are just as important as in-scope:

```
Common OOS patterns:
  - Third-party services (Shopify, AWS managed, Cloudflare)
  - Acquired companies (acq.example.com)
  - Specific subdomains (dev.example.com, staging.example.com)
  - Specific paths (/admin, /internal)
  - Specific IP ranges
  - Specific environments (test, staging, UAT)
  - Employee devices
  - Physical premises
  - Social engineering
  - Specific bug classes (DoS, spam, etc.)
```

### Step 6: Wildcard Expansion Check

When scope includes *.example.com, manually verify:

- Does www.example.com resolve? (Yes, it's in scope)
- Does admin.example.com resolve? (Yes, it's in scope)
- Does a.b.example.com resolve? (Usually yes — but verify)
- Does example.com itself resolve? (Sometimes excluded)
- Does example.io or example.net resolve? (No — different TLD)

### Step 7: Check for Embedded Rules

Programs sometimes hide scope rules in:

- Program policy documents.
- FAQ sections.
- Attached PDF files.
- Community posts.
- Known disclosure reports.

### Step 8: Check the Rate Limit and Testing Rules

Scope isn't just about domains. It includes:

- Allowed testing methods.
- Rate limits.
- Time restrictions.
- Data handling requirements.
- Vulnerability types to avoid.

### In-Scope Pattern Reference

```
Wildcard Domain:
  *.example.com
  Matches: www.example.com, api.example.com, admin.example.com, a.b.example.com
  Does NOT match: example.com, example.io, example.net

Specific Subdomain:
  www.example.com
  Matches: www.example.com ONLY
  Does NOT match: api.example.com, example.com

Root Domain:
  example.com or *.example.com
  Matches: example.com (usually), www.example.com (usually)
  Check program details for specific inclusion

Path-Scoped:
  example.com/api/v2
  Matches: example.com/api/v2/users, example.com/api/v2/orders
  Does NOT match: example.com/api/v1, example.com, api.example.com

API Endpoint:
  api.example.com/graphql
  Matches: api.example.com/graphql
  Does NOT match: api.example.com/rest, www.example.com

Mobile App:
  com.example.app (Android)
  com.example.app (iOS)
  Matches: The specified app package/bundle
  Does NOT match: com.example.otherapp

Smart Contract:
  0x1234567890abcdef1234567890abcdef12345678
  Matches: The specified contract address
  Does NOT match: Other contracts on the same chain
```

### Out-of-Scope Pattern Reference

```
Third-Party Services:
  Shopify hosted store
  AWS-managed services
  Cloudflare-protected origins (without proof)

Acquired Companies:
  subsidiary.example.com
  acquired-startup.io

Specific Environments:
  dev.example.com
  staging.example.com
  test.example.com
  uat.example.com
  qa.example.com

Specific Bug Classes:
  DoS/DDoS attacks
  Social engineering
  Physical security
  Spam
  Self-XSS

Restricted Paths:
  example.com/admin (unless explicitly allowed)
  example.com/internal

Employee/User Data:
  Employee accounts (without permission)
  Other users' private data
```

### Scope Entry Examples from Real Programs

```
Example 1: General Website Program
  In scope:
    - *.example.com
    - *.example.io
  Out of scope:
    - Acquired company example.net
    - Third-party services integrated via SSO
    - Rate limiting issues
    - CSRF on logout

Example 2: API-Only Program
  In scope:
    - api.example.com
    - developer.example.com/docs
  Out of scope:
    - www.example.com
    - *.example.com (other than listed)
    - Infrastructure vulnerabilities
    - Client-side issues

Example 3: Mobile + API Program
  In scope:
    - com.example.app (Android)
    - com.example.app (iOS)
    - api.example.com
  Out of scope:
    - Web application (www.example.com)
    - Decompiled source code redistribution
    - Physical device attacks

Example 4: Smart Contract Program
  In scope:
    - 0x1234...5678 (Vault contract)
    - 0xabcd...ef01 (Staking contract)
    - *.web.example.com (frontend)
  Out of scope:
    - Frontend vulnerabilities (separate program)
    - Testnet contracts
    - Governance attacks
    - Phishing/social engineering

Example 5: Infrastructure Program
  In scope:
    - 203.0.113.0/24
    - AS12345
    - *.example.com
  Out of scope:
    - Customer-hosted instances
    - Shared hosting infrastructure
    - Partner integrations
```

---

## 3. WILDCARD SCOPE INTERPRETATION

### What *.domain.com Actually Means

The wildcard `*.domain.com` is the most common (and most misunderstood) scope pattern. Understanding exactly what it covers is critical.

### The Technical Definition

In DNS, `*.domain.com` is a wildcard DNS record that matches any subdomain label. But in scope context:

```
*.domain.com matches:
  - www.domain.com (standard web)
  - api.domain.com (API endpoint)
  - admin.domain.com (admin panel)
  - mail.domain.com (mail server)
  - a.b.domain.com (nested subdomain)
  - anything.domain.com (any single label)
  - ANY-LABEL.domain.com (unrestricted)

*.domain.com does NOT match:
  - domain.com (the root — no subdomain)
  - domain.io (different TLD)
  - domain.net (different TLD)
  - domain.com.br (different TLD variant)
  - sub.domain.io (different TLD)
  - anything.else.com (different domain entirely)
```

### Does It Include the Root Domain?

**Controversy: Does *.domain.com include domain.com itself?**

Arguments for "yes":
- The root domain resolves as a web server.
- Most programs intend to cover both.
- Platform guidance often says "assume root is included."

Arguments for "no":
- Technically, `*.domain.com` does not match `domain.com`.
- Some programs explicitly list both.
- A few programs have rejected findings on the root.

**Best practice**: Check if the program lists `domain.com` separately. If not, ask via /scope or assume it is included until told otherwise. Most triagers consider the root in scope when wildcard is listed.

```
PROGRAM EXAMPLES:
  Good: Lists both "*.domain.com" and "domain.com" separately
  Better: Lists "domain.com and all subdomains"
  Ambiguous: Only lists "*.domain.com"
  Bad: Only lists "domain.com" (subdomains may be OOS)
```

### Does It Include All TLD Variants?

```
*.domain.com ONLY covers domain.com.
It does NOT cover:
  - domain.io
  - domain.net
  - domain.org
  - domain.co
  - domain.co.uk
  - domain.app
  - Any other TLD or ccTLD
```

If the program owns multiple TLDs, they will usually be listed separately:
```
In scope:
  *.domain.com
  *.domain.io
  *.domain.app
```

If you find a service on domain.io but only *.domain.com is in scope: **Stop. It's OOS.**

### Subdomain Depth

**Single-level wildcard (*.domain.com)**:
```
*.domain.com
  www.domain.com (1 level deep)
  api.domain.com (1 level deep)
  admin.domain.com (1 level deep)
  anything.domain.com (1 level deep)
```

**Nested subdomain interpretation**:
```
*.domain.com
  a.b.domain.com - Generally yes, wildcard includes all depths
  x.y.z.domain.com - Generally yes
```

**Why this matters**: Some programs explicitly use `*.domain.com` meaning only one level. But DNS wildcards naturally match any depth. When in doubt, ask.

### Recursive vs Single-Level Wildcard

Different programs may intend different things:

```
Program A: "*.example.com"
  Means: All subdomains at any depth
  Policy: "All owned domains and their subdomains"

Program B: "*.example.com"
  Means: Only single-level subdomains
  Policy: "Only direct subdomains, not nested"
```

**How to detect**: Check program FAQ. Look for disclosed reports that mention subdomain depth. When ambiguous, test carefully on a low-value nested subdomain first, or ask.

### Wildcard Variants

```
*.example.com             - All subdomains (standard)
**.example.com            - Unusual, likely means all depths
*.example.com/*           - All subdomains, all paths
*.*.example.com           - Two-level minimum (rare)
example.com               - Root domain only (usually)
example.com/**            - Root and all subdirectories
*.example.com:*           - All subdomains, all ports (rare)
```

### Wildcard Edge Cases

```
Case 1: CDN Subdomain
  Scope: *.example.com
  Asset: cdn12345.cloudfront.net (CNAME for assets.example.com)
  Verdict: The CNAME target (cloudfront.net) is NOT in scope.
           The DNS name (assets.example.com) IS in scope.

Case 2: SaaS Multi-Tenant
  Scope: *.example.com
  Asset: customer1.app.example.com
  Verdict: IN SCOPE — it matches *.example.com.
           But verify if shared infrastructure is excluded.

Case 3: Redirect Chain
  Scope: *.example.com
  Start: example.com/outbound -> https://tracker.analytics.io
  Verdict: example.com IS in scope.
           tracker.analytics.io IS NOT in scope.
           Do NOT follow redirects OOS.

Case 4: Wildcard Plus Specific Exclusions
  Scope: *.example.com
  OOS: admin.example.com
  Verdict: Everything under *.example.com EXCEPT admin.example.com.
           If you accidentally hit admin.example.com, stop and report.
```

### Wildcard Verification Commands

```powershell
# Test DNS resolution for various subdomains
Resolve-DnsName www.example.com
Resolve-DnsName api.example.com
Resolve-DnsName admin.example.com
Resolve-DnsName random-test-string-xyz.example.com

# Check if wildcard DNS is even configured
# If random-test-string-xyz.example.com resolves, wildcard DNS is active
# If it doesn't resolve, subdomains only exist where configured

# Check the root domain
Resolve-DnsName example.com

# Check for CNAME-based scope expansion
Resolve-DnsName assets.example.com -Type CNAME
```

### Platform-Specific Wildcard Rules

```
HackerOne:
  *.example.com generally includes example.com root.
  Wildcards match any label and any depth.
  Explicit OOS entries override wildcard matches.

Bugcrowd:
  *.example.com includes example.com root.
  "All subdomains" text in scope is equivalent to wildcard.
  Bugcrowd VRT has scope guidelines for common patterns.

Intigriti:
  Wildcard scope must be explicitly stated.
  Root domain and subdomains often listed separately.
  Path-based scope overrides domain-level scope.

Immunefi:
  Wildcard web scope includes all sub-paths.
  Smart contract scope is exact address only.
  Testnet is ALWAYS OOS unless explicitly stated.
```

---

## 4. THIRD-PARTY SERVICE DETECTION

### Why This Matters

Third-party services are almost always out of scope — even when they sit on an in-scope subdomain or serve an in-scope domain. Testing them violates scope and can affect other customers.

### CDN Ambiguity

Many targets use CDNs that serve both their content and other customers' content on the same IPs.

#### Cloudflare

```
Cloudflare Detection:
  Response headers: CF-RAY, Server: cloudflare
  If CF-RAY header present -> Cloudflare is proxying

Scope implication:
  The IPs are Cloudflare's, not the target's.
  Testing the IP directly is testing Cloudflare infrastructure.
  You need the origin IP (if obtainable) to test the actual server.

Acceptable tests through Cloudflare:
  - Web application testing through the CDN (scope depends on domain)
  - Header analysis
  - Application-layer bugs

NOT acceptable:
  - Attacking Cloudflare's infrastructure
  - Testing other Cloudflare customers on the same edge
  - Attempting to bypass Cloudflare to reach origin (without explicit permission)

Verification:
  curl -sI https://example.com | findstr "CF-RAY Server"
  If "CF-RAY" or "cloudflare" in Server -> Cloudflare
```

#### Fastly

```
Fastly Detection:
  Response headers: X-Served-By, X-Cache, X-Cache-Hits
  Server header often contains "Fastly"

Scope implication:
  Similar to Cloudflare — edge nodes are Fastly infrastructure.
  Target's content is hosted on Fastly's platform.

Acceptable tests:
  - Application testing on the domain
  - Cache behavior analysis

NOT acceptable:
  - Testing Fastly's POP infrastructure
  - Targeting other Fastly customers
  - Configuration probing beyond what the domain exposes
```

#### Akamai

```
Akamai Detection:
  Response headers: X-Akamai-Transformed, X-Akamai-Request-ID
  Server header: AkamaiGHost, AkamaiNetStorage

Scope implication:
  Akamai's global platform. Target is a customer.

Acceptable tests:
  - Application testing on the domain
  - Cache manipulation that affects only the target domain

NOT acceptable:
  - Testing Akamai's network
  - Accessing Akamai's configuration endpoints
  - Targeting other Akamai customers on shared infrastructure
```

#### Amazon CloudFront

```
CloudFront Detection:
  Response headers: X-Amz-Cf-Id, X-Amz-Cf-Pop
  Server header: CloudFront

Scope implication:
  CloudFront distribution belongs to target.
  But CloudFront itself is AWS infrastructure.

Acceptable tests:
  - Application testing on the domain
  - CloudFront configuration issues (only for the target's distribution)

NOT acceptable:
  - Testing AWS CloudFront service itself
  - Accessing other CloudFront distributions
  - S3 bucket discovery through CloudFront (unless S3 is in scope)
```

### SaaS Ambiguity

Many businesses run on SaaS platforms. The platform is third-party infrastructure.

#### Shopify

```
Shopify Detection:
  URL contains .myshopify.com or custom domain on Shopify
  Page source: {{ content_for_header }}, Shopify.shop
  Response header: X-ShopId, X-Shopify-Shop

Scope implication:
  The store domain may be in scope, but Shopify infrastructure is NOT.
  Testing Shopify admin panels is testing Shopify, not the target.

Acceptable:
  - Storefront testing (if domain is in scope)
  - Theme vulnerabilities (if they affect the target's store)
  - Business logic issues in the store (coupon abuse, etc.)

NOT acceptable:
  - Testing /admin paths (these are Shopify's)
  - Attacking Shopify's platform
  - Testing checkout infrastructure
  - Testing other stores on the same Shopify instance
```

#### Wix

```
Wix Detection:
  URL: username.wixsite.com/name or custom domain
  Page source: Wix.com, X-Wix-*
  Response headers: X-Wix-Application-Id

Scope implication:
  Wix-hosted content may be in scope by domain.
  Wix editing/admin infrastructure is NOT.

Acceptable:
  - Testing the public-facing site
  - Content issues on the live site

NOT acceptable:
  - Testing Wix editor infrastructure
  - Accessing Wix admin panels
  - Testing other Wix-hosted sites
```

#### Squarespace

```
Squarespace Detection:
  URL: username.squarespace.com or custom domain
  Footer: "Powered by Squarespace"
  Response headers often minimal — Squarespace strips many

Scope implication:
  Squarespace hosting means limited attack surface.
  Most server-side bugs are not applicable because Squarespace controls the stack.

Acceptable:
  - Client-side issues (XSS, CSRF) on the custom domain
  - Business logic issues

NOT acceptable:
  - Server-side injection (it's Squarespace's server)
  - Squarespace infrastructure testing
  - Accessing Squarespace admin
```

#### WordPress.com (Hosted)

```
WordPress.com Detection:
  URL: name.wordpress.com or custom domain with WordPress.com hosting
  Response headers: X-hacker (WordPress.com-specific)

Scope implication:
  Distinguish between:
  - WordPress.com (hosted): WordPress infrastructure
  - Self-hosted WordPress (wp.org): Target's own server

WordPress.com hosted:
  - Limited scope — most server-side bugs are WordPress.com's responsibility
  - wp-admin is WordPress.com infrastructure
  - Plugin vulnerabilities may be target-specific if they use custom plugins

Self-hosted WordPress:
  - Full server testing (if server is in scope)
  - Plugin, theme, core testing on target's instance
  - Must not affect other sites on shared hosting
```

### Cloud Provider Ambiguity

When a target hosts on AWS/GCP/Azure, the cloud infrastructure is not in scope.

#### AWS

```
AWS Detection:
  IP ranges: Check against AWS IP ranges
  Endpoints: .amazonaws.com, .cloudfront.net, .elasticbeanstalk.com
  Headers: x-amz-*, x-amzn-RequestId
  Bucket URLs: .s3.amazonaws.com, .s3.region.amazonaws.com

Scope implication:
  AWS services used BY the target may be testable.
  AWS itself is NEVER in scope.

Acceptable:
  - S3 bucket permission testing (only target's buckets)
  - API Gateway endpoint testing (only target's APIs)
  - Lambda function testing (only target's functions)
  - Cognito misconfigurations (only target's user pools)

NOT acceptable:
  - AWS infrastructure attacks
  - IMDS (metadata service) exploitation (unless explicitly allowed)
  - Cross-account access attempts
  - EC2 hypervisor attacks
  - DNS rebinding against AWS services
  - Testing other AWS customers' resources

Verification:
  # Check if an IP is within AWS ranges
  curl -s https://ip-ranges.amazonaws.com/ip-ranges.json |
    Select-String -Pattern "203.0.113.0/24"
```

#### GCP

```
GCP Detection:
  Endpoints: .appspot.com, .cloudfunctions.net, .run.app
  IP ranges: Known GCP ranges
  Headers: via: 1.1 google, x-cloud-trace-context

Scope implication:
  GCP services used by target may be testable.
  GCP infrastructure itself is NOT.

Acceptable:
  - Cloud Storage bucket testing (only target's buckets)
  - Cloud Function testing (only target's functions)
  - Firebase misconfigurations (only target's projects)
  - App Engine testing (only target's apps)

NOT acceptable:
  - GCP infrastructure
  - Google's authentication infrastructure
  - Other GCP customers' resources
  - Metadata server exploitation (169.254.169.254)
```

#### Azure

```
Azure Detection:
  Endpoints: .azurewebsites.net, .azureedge.net, .azurefd.net
  IP ranges: Known Azure ranges
  Headers: x-ms-request-id, x-ms-version
  Auth: x-ms-auth-token

Scope implication:
  Azure services used by target may be testable.
  Azure itself is NEVER in scope.

Acceptable:
  - Azure Blob storage testing (only target's containers)
  - Azure Function testing (only target's functions)
  - Azure AD misconfigs (only target's tenant)
  - App Service testing (only target's apps)

NOT acceptable:
  - Azure infrastructure attacks
  - Other Azure customers' resources
  - Azure AD cross-tenant attacks (unless chained through target)
  - Azure Resource Manager manipulation (without target credentials)
```

### Third-Party Service Verification Script

```powershell
function Test-ThirdParty {
    param([string]$Domain)

    $headers = curl -sI "https://$Domain" 2>&1

    $indicators = @()

    # Cloudflare
    if ($headers -match "CF-RAY|cloudflare") {
        $indicators += "Cloudflare"
    }

    # Fastly
    if ($headers -match "Fastly|X-Served-By|X-Cache-Hits") {
        $indicators += "Fastly"
    }

    # Akamai
    if ($headers -match "AkamaiGHost|X-Akamai") {
        $indicators += "Akamai"
    }

    # CloudFront
    if ($headers -match "CloudFront|X-Amz-Cf-Id") {
        $indicators += "CloudFront"
    }

    # AWS
    if ($headers -match "x-amz-|x-amzn-") {
        $indicators += "AWS (generic)"
    }

    # Google/GCP
    if ($headers -match "google|GWS|x-cloud-trace") {
        $indicators += "Google/GCP"
    }

    # Azure
    if ($headers -match "x-ms-|Azure") {
        $indicators += "Azure"
    }

    # Wix
    if ($headers -match "X-Wix-") {
        $indicators += "Wix"
    }

    # Shopify
    if ($headers -match "X-Shopify|X-ShopId") {
        $indicators += "Shopify"
    }

    return $indicators
}

# Usage
# Test-ThirdParty "example.com"
```

### The Third-Party Decision Tree

```
Is the asset an in-scope domain?
  YES: Continue
  NO: STOP — OOS

Is the asset hosted on a third-party platform?
  YES:
    Is the platform itself in scope? (Almost never)
      YES: Test the platform
      NO:
        Can I test the target's content without testing the platform?
          YES: Proceed carefully
          NO: STOP — OOS
  NO: Continue normal testing

Does the test involve sending requests to third-party IPs?
  YES:
    Is this necessary for the finding? (e.g., SSRF callback)
      YES: Use program-approved callback (interact.sh, Burp Collaborator)
      NO: Find a way that doesn't hit third parties
  NO: Continue
```

### Redirection Third-Party Risks

Many redirect chains cross scope boundaries:

```
Example redirect chain:
  example.com/click?url=https://partner-site.com
    -> 302 redirect to https://partner-site.com/landing
      -> Third-party site

Even though the redirect STARTED on an in-scope domain:
  - The redirect TARGET is OOS
  - Do NOT follow the redirect
  - Do NOT test the target
  - Report the redirect as an open redirect ONLY if that's in scope
```

### SSRF and Third-Party Implications

When testing SSRF:

- Your payloads might hit third-party services.
- Your callback server/OOB must be your own controlled infrastructure.
- Do NOT make SSRF payloads target AWS metadata unless in scope.
- SSRF that hits other customers on the same hosting platform is OOS.

**SSRF Scope Rule**: If your SSRF payload makes a request to ANY IP/domain that is not in scope, you are violating scope — UNLESS it's your own controlled callback server used solely for detection.

### Shared Hosting Risks

```
Shared hosting scenario:
  Target is on a shared IP with 500+ other domains.

Testing implications:
  - You can test the target's application on the shared IP.
  - You CANNOT test other domains on the same IP.
  - You CANNOT port-scan the shared IP aggressively.
  - Rate limiting on shared IP affects other customers — be careful.
  - Any vulnerability that accesses other customers' data is OOS.
```

### CDN/SaaS Summary Table

| Provider | Detectable By | Can Test Target? | Can Test Infrastructure? |
|----------|---------------|------------------|-------------------------|
| Cloudflare | CF-RAY header, Server header | Yes (through CF) | No |
| Fastly | X-Served-By, X-Cache | Yes | No |
| Akamai | X-Akamai headers | Yes | No |
| CloudFront | X-Amz-Cf-Id | Yes | No |
| Shopify | X-Shopify headers | Storefront only | No |
| Wix | X-Wix headers | Public site only | No |
| Squarespace | Minimal headers, footer | Client-side only | No |
| WordPress.com | X-hacker header | Limited | No |
| AWS (generic) | x-amz headers | Target resources | No |
| GCP | x-cloud-trace | Target resources | No |
| Azure | x-ms headers | Target resources | No |

---

## 5. SCOPE VERIFICATION PROTOCOL

### The /scope Command

Most platforms have a scope verification mechanism:

```
HackerOne:
  /scope in report comments — asks triage to confirm scope of a specific asset
  Use when uncertain about a specific domain/path

Bugcrowd:
  /scope — returns the current scope for the program
  Available in the program page and report interface

Intigriti:
  /scope — similar functionality
  Contact support for scope questions

Immunefi:
  /scope — available in Discord/Telegram bots
  Also available via project page
```

### When to Use /scope

```
Good times to use /scope:
  - Asset is logically owned by target but not listed
  - Subdomain of an in-scope domain but feels like third-party
  - Found new domain during recon that seems related
  - Scope is ambiguous (wildcard vs specific)
  - Program acquisition recently occurred
  - Third-party service that might be in scope

Bad times to use /scope:
  - Asking about every single subdomain (annoying)
  - Asking when answer is obvious from scope page
  - Asking about clearly OOS assets
  - Spamming /scope repeatedly
```

### Manual Verification via security.txt

The security.txt file (RFC 9116) often contains scope and contact info:

```powershell
# Fetch security.txt
curl -s https://example.com/.well-known/security.txt
curl -s https://example.com/security.txt

# Expected content:
# Contact: https://hackerone.com/example
# Encryption: https://example.com/pgp-key.txt
# Policy: https://example.com/vulnerability-disclosure-policy
# Scope: https://example.com/scope
# Acknowledgments: https://example.com/hall-of-fame
```

### Hunter.io and Email Verification

For less formal programs, email contacts can clarify scope:

```
When emailing:
  Subject: Scope Question — [Program Name]
  Body: "
  Hello,
  I am a security researcher interested in testing [Program].
  Could you please clarify whether [specific asset] is in scope?
  I found this asset while researching and want to confirm
  before testing.
  Thank you.
  "
```

**Warning**: Document any email response about scope. Save it as evidence.

### Cross-Referencing Multiple Sources

Always verify scope from at least 2 sources:

```
Source 1: Platform program page (primary)
Source 2: security.txt (if available)
Source 3: Program policy documents (attached to program)
Source 4: Public disclosure archive (see previous reports)
Source 5: Program website / bug bounty page
```

### Verification Checklist

Before testing ANY asset:

```
[ ] Asset matches a scope entry exactly
[ ] Asset is not listed in out-of-scope section
[ ] Asset is owned by the target company (WHOIS check)
[ ] Asset is not a third-party service
[ ] Asset is not on shared infrastructure
[ ] No recent scope changes that would exclude it
[ ] If uncertain: /scope command sent
```

### Automated Scope Verification

```powershell
function Test-InScope {
    param([string]$Url, [string]$ScopeFile)
    $inScope = $false
    $scopePatterns = Get-Content $ScopeFile

    $hostname = ([System.Uri]$Url).Host

    foreach ($pattern in $scopePatterns) {
        $pattern = $pattern.Trim()
        if ($pattern -eq $hostname) {
            $inScope = $true
            break
        }
        if ($pattern -like "*.*" -and $hostname -like $pattern.Replace("*", "*")) {
            $inScope = $true
            break
        }
        if ($pattern -like "*.$hostname") {
            $inScope = $true
            break
        }
    }
    return $inScope
}
```

### Time-Boxed Verification

Don't agonize over scope indefinitely:

```
Time budget for scope verification:
  First program of day: 10 minutes
  Each additional program: 5 minutes
  Ambiguous asset: 15 minutes max
  If still uncertain after budget: /scope or move on
```

### Scope Verification at Scale

When running automated tools:

```powershell
# Option 1: Proxy through Burp with scope configured
# Burp will drop OOS requests automatically

# Option 2: Pre-filter domains against scope file before scanning
Get-Content "all-subdomains.txt" | Where-Object {
    $d = $_; (Get-Content "scope-list.txt") | Where-Object {
        $p = $_; $d -like $p.Replace("*", "*")
    }
} | Set-Content "in-scope-domains.txt"
```

---

## 6. IP-BASED SCOPE

### When Targets List IP Ranges

Some programs (especially infrastructure, hosting, or CDN companies) list IP ranges instead of domains:

```
In scope:
  203.0.113.0/24
  198.51.100.0/22
  192.0.2.0/28
```

### Parsing CIDR Notation

CIDR (Classless Inter-Domain Routing) notation: `IP/Prefix`

```
/24 = 256 IPs (255 usable)
/22 = 1024 IPs
/28 = 16 IPs (14 usable)
/16 = 65536 IPs
/32 = 1 IP
```

### ASN Identification

When scope lists an ASN (Autonomous System Number):

```
In scope:
  AS12345 — Example Corp

ASN scope means:
  ALL IPs in that ASN are in scope
  REGARDLESS of domain names assigned to them
```

```powershell
# Find ASN for a domain/company
# Using whois
whois -h whois.cymru.com "AS12345"

# Get all prefixes for an ASN
curl -s "https://api.bgpview.io/asn/12345/prefixes" |
  ConvertFrom-Json |
  Select-Object -ExpandProperty data |
  ForEach-Object { $_.ipv4_prefixes.ipv4 }
```

### IP to Domain Resolution

Finding domains on IPs in scope:

```powershell
# Reverse DNS for a single IP
Resolve-DnsName -Name $IP -Type PTR

# Mass reverse DNS
$ips = Get-Content "in-scope-ips.txt"
foreach ($ip in $ips) {
    try {
        $result = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
        Write-Output "$ip -> $($result.NameHost)"
    } catch {
        Write-Output "$ip -> No PTR record"
    }
}
```

### Cloud Provider IP Ranges

Know which IPs belong to cloud providers:

```
AWS IP ranges: https://ip-ranges.amazonaws.com/ip-ranges.json
GCP IP ranges: https://www.gstatic.com/ipranges/cloud.json
Azure IP ranges: https://download.microsoft.com/download/.../ServiceTags_Public.json
Cloudflare IPs: https://www.cloudflare.com/ips-v4
```

If scope lists IP ranges that belong to cloud providers:

```
Scenario:
  Scope: 203.0.113.0/24
  These IPs are in AWS range

Verdict:
  The IPs may be in scope, but AWS infrastructure is not.
  You can test services on those IPs as they relate to the target.
  You cannot test AWS itself on those IPs.
```

### IP Scope vs Domain Scope Overlap

```
Scenario:
  Scope says:
    In scope: 203.0.113.0/24
    Out of scope: *.example.com

  What if 203.0.113.5 hosts example.com?

Verdict:
  The IP is in scope (it's in the CIDR range).
  The domain example.com is OOS (explicitly listed).
  You CAN test the IP, but NOT the domain.
  Any finding on the IP should reference the IP, not the domain.
```

### IP-Based Testing Rules

```
When testing IP-based scope:

1. Document the IP, not the domain, in your findings.
2. If the IP resolves to multiple domains, only test as it relates to the target.
3. Do NOT test other services running on the same IP (unless they belong to target).
4. Do NOT port-scan the entire range aggressively.
5. Rate limit applies to IPs too.
6. Shared hosting on IP-based scope still means shared hosting rules apply.
```

### IP Scope Verification

```powershell
function Test-IPInScope {
    param(
        [string]$IP,
        [string[]]$ScopeCIDRs
    )
    $ipBytes = [System.Net.IPAddress]::Parse($IP).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)

    foreach ($cidr in $ScopeCIDRs) {
        $parts = $cidr.Split('/')
        $prefix = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
        [Array]::Reverse($prefix)
        $prefixInt = [System.BitConverter]::ToUInt32($prefix, 0)
        $maskBits = [int]$parts[1]
        $maskInt = [uint32](([math]::Pow(2, $maskBits) - 1) * [math]::Pow(2, 32 - $maskBits))

        if (($ipInt -band $maskInt) -eq ($prefixInt -band $maskInt)) {
            return $true
        }
    }
    return $false
}

# Usage
# Test-IPInScope "203.0.113.5" @("203.0.113.0/24", "198.51.100.0/22")
```

---

## 7. ACQUIRED COMPANY SCOPE

### After Acquisitions: Are Acquired Assets in Scope?

The #1 scope ambiguity situation. When Company A acquires Company B:

```
Question: Are Company B's assets now in scope?
Answer: NOT UNLESS explicitly listed.
```

### The Acquisition Scenario

```
Scenario:
  - You've been testing Company A (in scope)
  - Company A acquires Company B
  - Company B has platform1.com, platform2.com

Day 1 after acquisition announcement:
  - Company B's assets are NOT automatically in scope
  - The program must update scope to include them

Day 30 after acquisition close:
  - Still NOT in scope unless program updates
  - Some programs never add acquired assets

Day 365:
  - Still NOT in scope unless explicitly updated
  - Any test on platform1.com is OOS
```

### Transition Periods

During acquisition transitions, assets are in a gray zone:

```
Phase 1: Announcement
  - News breaks that Company A acquired Company B
  - No scope change -> Do NOT touch Company B's assets
  - Risk: Platform sees requests to Company B's domains

Phase 2: Integration begins
  - Company B's domains start redirecting to Company A
  - Still OOS unless scope changed
  - Do NOT follow redirects to Company B domains

Phase 3: Brand migration
  - Company B's products are now branded under Company A
  - Some infrastructure may share IPs
  - STILL verify scope hasn't changed

Phase 4: Scope update
  - Only when program page explicitly adds Company B's assets
  - Only then can you test them
```

### Brand vs Parent Company Scope

Common pitfall:

```
Out of scope:
  "Parent company assets" — Unless parent is listed
  "Subsidiary assets" — Unless subsidiary is listed
  "Affiliated brands" — Unless each brand is listed
  "Sister companies" — Unless listed

In scope:
  "All Company A domains and subdomains"
  "All subsidiaries of Company A" (only if explicitly stated)
```

### How to Verify After Acquisition

```powershell
# Check WHOIS to confirm ownership
whois acquired-company.com | findstr "Organization"

# Check if they share DNS infrastructure
Resolve-DnsName company-a.com | findstr "Address"
Resolve-DnsName acquired-company.com | findstr "Address"
# If IPs match and scope hasn't been updated: Still OOS
```

### Acquisition Disclosure Example

```
Real-world example:
  Target: example.com
  Target acquires: startup.io

  Scope before acquisition:
    In: *.example.com
    Out: All third-party services

  Scope after acquisition (if updated):
    In: *.example.com, *.startup.io
    Out: Third-party services

  Scope after acquisition (if NOT updated — common):
    In: *.example.com
    Out: *.startup.io (not listed), third-party services
```

### The Rebrand Problem

Company A acquires Company B and rebrands their product:

```
Scenario:
  Company A owns example.com
  Acquires Company B which runs better-product.com
  Rebrands Company B's product as "Example Product"
  better-product.com now redirects to example.com/better-product

Scope analysis:
  better-product.com -> Not in scope (unless added)
  example.com/better-product -> In scope (matches *.example.com)
  BUT: Testing better-product.com directly -> OOS
```

### Multiple Brands, Same Company

Some companies have many brands:

```
Company "Unified Corp" owns:
  brand-a.com
  brand-b.com
  brand-c.com

Program scope: "*.brand-a.com"
  brand-b.com: OOS
  brand-c.com: OOS
  shared-infra.brand-a.com: In scope (but verify it doesn't serve other brands)
```

### Testing Strategy During Acquisition Uncertainty

```
When unsure about acquired assets:

1. STOP testing the potentially acquired asset.
2. Check program page for scope update.
3. Check program announcements/updates.
4. Use /scope to ask.
5. If no response: Do not test.
6. Document the date you checked.
7. Re-check periodically if acquisition integration takes months.
```

### Acquisition Scope Checklist

```
[ ] Check program page for new in-scope assets
[ ] Check program page for new out-of-scope entries
[ ] Check program announcements/posts
[ ] Check if acquired company has its own bug bounty
[ ] Check WHOIS for common ownership/registration
[ ] If uncertain, use /scope or contact program
[ ] Document all checks with dates
[ ] Do NOT test until scope is confirmed
```
