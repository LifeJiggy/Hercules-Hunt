# Scope — <target>

## In scope

- (paste in-scope asset list here)

**Instructions for filling this section:**
1. Copy the in-scope asset list from the program page verbatim
2. If the list uses wildcards (*.target.com), expand them using subdomain enumeration
3. Note the asset type for each entry: web, API, mobile (Android/iOS), cloud, source code
4. Note the environment: production, staging, QA, development
5. Flag any "all subdomains" wildcards — these are the highest-value scope grants

## Out of scope

- (paste OOS list here, including excluded bug classes)

**Instructions for filling this section:**
1. Copy the OOS list exactly from the program page
2. Note any excluded bug classes (DoS, clickjacking, physical, social engineering)
3. Note any excluded asset types (third-party services, acquired companies, legacy systems)
4. Note any testing restrictions (rate limits, automated scanning bans, time windows)
5. IMPORTANT: Read this list before EVERY session. OOS violations burn platform standing.

## Focus areas

- (paste Focus Areas / accepted impacts — highest-leverage targets)

**Instructions for filling this section:**
1. Copy the Focus Areas from the program page
2. If the program doesn't list Focus Areas, infer from:
   - Disclosed reports: what bugs has this program paid for?
   - Job postings: what technologies are they hiring for? (new stack = less mature security)
   - Recent changelogs: what features were recently shipped? (new features = more likely buggy)
   - Tech stack: what frameworks/libraries are they using? Any with known CVEs?
3. Focus Areas are your highest-ROI targets — spend 70% of your time here

## Bounty bands

| Severity | Band |
|---|---|
| P1 (Critical) | |
| P2 (High) | |
| P3 (Medium) | |
| P4 (Low) | |
| P5 (Info) | (often unrewarded) |

**Instructions:**
1. Fill in the dollar amounts from the program page
2. If bands are not published, look for disclosed reports to infer payouts
3. Note any bonuses: chain bonuses, first-finding bonuses, monthly bonuses

## Account / testing setup

- **Test account email:**
- **Test account uid:**
- **Production vs QA:**
- **Mobile builds:** (Android APK / iOS IPA URLs if provided)
- **Authentication notes:** (SSO, MFA enrollment, etc.)

---

## Scope Parsing Methodology

Every scope document is written differently. Some programs are explicit, some are vague, some are intentionally confusing. This methodology handles all formats.

### Step 1: Categorize Every Asset

Create a categorized list of all in-scope assets:

```
target.com (root domain)
*.target.com (all subdomains)
api.target.com (API)
app.target.com (web application)
m.target.com (mobile web)
android.target.com (Android app API)
ios.target.com (iOS app API)
```

### Step 2: Identify Scope Boundaries

For each asset, determine:
- **Ownership:** Is this owned by the target or a third-party vendor? (Third-party requires explicit inclusion)
- **Environment:** Production, staging, dev, or internal? (Testing on internal may be explicitly allowed or forbidden)
- **Authentication:** Does this require a test account? (Some assets are public, some require credentials)
- **Data sensitivity:** What data flows through this asset? (PII, financial, health — affects disclosure requirements)

### Step 3: Map the Wildcards

**`*.target.com`** — This means ALL subdomains of target.com. Including:
- blog.target.com
- app.target.com
- api.target.com
- admin.target.com
- dev.target.com
- staging.target.com
- Any subdomain discovered during recon

**Verification:** Before testing a subdomain under a wildcard, verify it resolves and serves target-owned content. Subdomain takeover risk increases if the subdomain points to a third-party service (S3, Heroku, GitHub Pages) that the target no longer controls.

**`target.com/*`** — Path wildcard. Only the specified path and its children are in scope. The rest of the domain is OOS.

**Specific subdomains only** — Only the listed subdomains are in scope. All others are OOS, even if they share the same root domain.

### Step 4: Identify Scope Traps

Common scope wording that trips up hunters:

| Phrase | What It Actually Means |
|--------|----------------------|
| "All subdomains of target.com are in scope" | Great — but verify each one resolves to target infrastructure before testing |
| "target.com and its subdomains" | Same as above — but check the wording carefully |
| "*.target.com" | The standard wildcard — all subdomains |
| "target.com" (alone) | ONLY the root domain. Subdomains are OOS unless explicitly included |
| "All assets listed below..." | Read the list carefully. If something's not on the list, it's OOS |
| "Third-party services are OOS" | Check if they use Okta, Auth0, AWS, GCP, Cloudflare — those services are OOS even if the target configures them |
| "No automated scanning" | Manual testing only. Burp's Intruder might be considered automated |
| "DoS testing is strictly prohibited" | Any test that could cause a denial of service, even unintentionally, is forbidden |
| "Rate limiting: please be respectful" | This usually means 1-5 requests per second max |
| "Testing on production is allowed" | But check if they have a QA/staging environment you should use instead |
| "Testing on production is not allowed" | Find the QA/staging environment for active tests, but recon (passive) on production may be OK |
| "Acquired companies are OOS" | Check if the target has acquired any companies recently — those assets are off-limits |
| "CVEs are not eligible" | You need to find implementation bugs, not version-based vulnerabilities |
| "Please do not use public proof-of-concept code" | You need to develop your own exploit |

---

## Asset Discovery Checklist

Before starting any test, confirm:

| Check | Done | Notes |
|-------|------|-------|
| Root domain resolves | ☐ | |
| All wildcard subdomains enumerated | ☐ | |
| Each subdomain verified as target-owned | ☐ | |
| No OOS assets in the enumerated list | ☐ | |
| Bug class exclusions noted | ☐ | |
| Focus areas identified | ☐ | |
| Bounty bands recorded | ☐ | |
| Test account created/accessible | ☐ | |
| Rate limits understood | ☐ | |
| Testing window confirmed | ☐ | |

---

## CDN/WAF Bypass and Scope Expansion

Sometimes the target's scope is behind a CDN (Cloudflare, Akamai, Fastly) or WAF. Finding the real origin can give you access to endpoints that are blocked from the CDN front.

### Origin Discovery Techniques

1. **Certificate Transparency Logs:** Search crt.sh for the domain. Certificate logs often reveal origin IPs, internal subdomains, and staging environments that aren't behind the WAF.

2. **DNS History:** Check SecurityTrails, DNSDumpster, and AlienVault OTX for historical DNS records. If the target used to have a different IP before the CDN was deployed, that IP might still serve content.

3. **Shodan/Censys:** Search for the target's SSL certificate hash. Shodan will show all IPs that serve that certificate — including origin servers that the CDN protects.

4. **Subdomain Brute-Force:** Some subdomains (origin.target.com, direct.target.com, lb.target.com) point to the origin server. Add these to your ffuf wordlist.

5. **Error-Based Disclosure:** Send a request with a non-standard Host header or an invalid SNI. Some CDN/WAF configurations leak the origin IP in error responses.

6. **SMTP/SPF Records:** Check the target's SPF/DMARC records. These often list origin IPs that are allowed to send mail from the domain.

7. **Cloud Buckets:** Some targets store content in S3/GCS/Azure Blob buckets. These are usually not behind the CDN. If you find a bucket, test it directly.

### Scope Warning

Origin bypass only applies when:
- The origin still serves the target's content
- The origin is within the target's scope (owned by the target, same root domain)
- You're not accessing data or endpoints that the CDN was specifically blocking

Finding the origin does NOT make OOS assets in scope. It only gives you a different route to in-scope assets.

---

## Bug Class Exclusions Analysis

Programs commonly exclude certain bug classes. Understanding WHY they're excluded helps you find the exceptions:

| Excluded Class | Why Exploiting the Exclusion Works |
|----------------|-----------------------------------|
| Self-XSS | Chain it with CSRF — the XSS becomes exploitable against other users |
| CSRF on non-sensitive actions | — but the program didn't exclude CSRF on SENSITIVE actions. Find those. |
| Clickjacking | — unless you can chain it with a permissions API or a sensitive action |
| Missing SPF/DMARC | — unless you can demonstrate actual email spoofing (send to a domain you control) |
| Rate limiting | — unless the missing rate limit is on a sensitive endpoint (password reset, 2FA, payment) |
| Missing security headers | — unless the missing header enables a specific attack (XSS via missing CSP) |
| HTTPS mixed content | — unless you can hijack the HTTP resource |
| Information disclosure | — unless the disclosed info enables further attacks (SSRF, cloud metadata) |
| Open redirect | — unless you can chain it with OAuth (theft of auth code) |

**Rule:** Just because a class is excluded doesn't mean ALL instances of it are excluded. Find the exception — the excluded class on a non-excluded endpoint, or the excluded class that enables a chain.

---

## Focus Areas Exploitation Strategy

Once you've identified the Focus Areas, develop a targeted strategy for each:

### Auth / Login Focus
- Rate limiting on login (credential stuffing vector)
- Password reset token leakage (referer header, URL param in logs)
- MFA bypass (direct navigation post-MFA, OTP replay, recovery code abuse)
- Session fixation (can you set a victim's session?)
- OAuth misconfiguration (redirect_uri validation, state parameter)

### Payments / Financial Focus
- IDOR on payment history, invoices, refunds
- Race condition on coupon/gift card redemption
- Mass assignment on order total, quantity, discount
- Business logic: negative numbers, decimal handling, quantity overflow
- Currency manipulation (pay in one currency, refund in another)

### Data Export / Privacy Focus
- IDOR on CSV/PDF export (export another user's data)
- CSV injection (formulas in exported data)
- SSRF on export-to-URL features
- Rate limiting on data export (data exfiltration via slow but steady export)
- Missing pagination limits (export all users' data in one request)

### Admin / Privilege Focus
- Horizontal privilege escalation (access another admin's workspace)
- Vertical privilege escalation (user → admin)
- Missing auth on admin endpoints
- Admin-only data in client-side code (hidden fields, JS bundles)
- Admin impersonation features (can you assume another user's identity?)

---

## Program-Specific Quirks

Different programs have different priorities and sensitivities. Note these when you start a target:

**HackerOne:**
- Programs publish disclosed reports — READ THEM first. The methodology is often directly transferable.
- Some programs have "priority" or "focus" tags on certain bug classes.
- Collaborative disclosure is encouraged — you can work with the program on the fix.

**Bugcrowd:**
- VRT (Vulnerability Rating Taxonomy) determines base severity. Know the VRT categories before submitting.
- Some programs use VRT-derived automatic severity — your report's severity is calculated from the VRT, not your assessment.
- "Priority" targets are listed in the program brief — these get faster triage and higher payouts.

**Intigriti:**
- Known for detailed scope documents. Read every word — they're usually precise.
- Some programs have "challenge" flags for particularly difficult findings.

**Immunefi:**
- Smart contract focus. Scope is usually well-defined contract addresses.
- Severity uses the Immunefi Vulnerability Severity Classification System (not CVSS).
- Payouts are typically in crypto (USDC, ETH).

**Private programs:**
- Scope can be negotiated. If you find a legitimate asset you think should be in scope, ask the program.
- Relationships matter. A well-written report builds trust for future submissions.

---

## Testing Window Guide

| When | What to Do |
|------|------------|
| Target just launched a new feature | Hunt NOW. New code is the most buggy code. |
| Target just acquired a company | Hunt the acquired company's assets. Integration bugs are common. |
| Target had a recent breach | Expect heightened monitoring. Be extra careful about OOS. Also expect more bug bounty investment. |
| Target has a major event (conference, product launch, earnings call) | Don't test during the event. Avoid causing incidents during high-pressure windows. |
| Night/weekend | Lower traffic means less impact when testing. But respect timezone — test during the target's business hours for critical impact testing. |
| End of quarter | Some programs have payout delays at end of quarter (budget cycles). Check before submitting. |
| Holiday season | Fewer triagers working. Expect slower triage. |

---

## Scope Edge Cases

### Wildcards with Exceptions

Some programs list scope as `*.target.com` but then exclude specific subdomains:

```
In scope: *.target.com
Out of scope: admin.target.com, *.corp.target.com
```

This creates two edge cases:
1. **DNS-based exclusion:** `admin.target.com` is excluded, but `admin-beta.target.com` is under the wildcard. Is it in scope? Technically yes, but expect pushback. Better to ask the program.
2. **Glob exclusion:** `*.corp.target.com` excludes ALL subdomains of `corp.target.com`. But is `corp.target.com` itself included? The root of an excluded subdomain is ambiguous — ask for clarification.

### Acquired Companies

When Target A acquires Company B:
- Company B's assets may NOT be in scope unless explicitly listed
- Integration points between A and B are often the buggiest code, but assets from B may be OOS
- Check: does the program specifically call out the acquisition? If not, assume B's assets are OOS
- Exception: if B's domain is a subdomain of A (e.g., `b.target.com`), it's covered by the wildcard

### Third-Party/SaaS Scope

Many targets use third-party services:
- Auth0/Okta for authentication
- AWS/GCP/Azure for cloud infrastructure
- Stripe/Braintree/Adyen for payments
- Cloudflare/Fastly/Akamai for CDN
- Zendesk/Intercom for customer support
- GitHub/GitLab for source code

**General rule:** The SERVICE is OOS. The target's CONFIGURATION of the service is in scope.

Example: Stripe is OOS (you can't hack Stripe), but a payment processing bug in how the target uses Stripe's API IS in scope (the target's code, not Stripe's).

Exception: If the program explicitly lists a third-party service as in scope (e.g., "our GitHub repos are in scope"), test it.

### API-Only Scope

Some programs scope only their API, not the web application:

```
In scope: api.target.com
Out of scope: www.target.com, app.target.com
```

This means:
- You can test the API directly (curl, Postman, Burp)
- You CANNOT test the web application that CONSUMES the API
- You CAN look at the web app's client-side code to understand API endpoints (passive recon is usually allowed)
- Rate limits on the API may be stricter — the program expects automated testing

### Mobile-Only Scope

```
In scope: Android APK, iOS IPA
Out of scope: All web properties
```

Strategy:
- Download the APK/IPA and decompile (jadx, apktool)
- Extract hardcoded API endpoints, secrets, and auth tokens from the binary
- Test the API endpoints that the mobile app uses
- The WEB property that serves the same API may or may not be in scope — check carefully

### Source Code Scope

Some programs include source code access:

```
In scope: github.com/target/* repositories
```

Rules:
- You can read the code, not scan it automatically (unless explicitly allowed)
- You can test against live instances of the code (if the live instance is also in scope)
- You CANNOT disclose the code or any secrets found in the code (obviously)
- Secrets found in code are usually a separate finding (hardcoded credentials) — follow disclosure protocol

### VDP vs Bug Bounty Scope

A Vulnerability Disclosure Program (VDP) has different rules than a paid bug bounty program:

| Dimension | Bug Bounty | VDP |
|-----------|------------|-----|
| Scope | Usually broad | Usually narrow |
| Payout | Yes | No |
| Triage speed | Fast (incentivized) | Slow |
| Expected evidence | Full PoC | Basic reproduction |
| Chain expectation | Yes | Usually not |
| Disclosure policy | Program-dependent | Typically more restrictive |

VDP scope tends to be narrower and more conservative. Treat VDP engagements as "low-risk, low-reward" — test carefully, expect less feedback.

### Scope Negotiation

For private programs, scope is sometimes negotiable:

**When to negotiate:**
- You found a legitimate security issue on an asset that SHOULD be in scope but isn't listed
- The asset is owned by the target, serves the target's users, and handles the target's data
- You have a relationship with the program (previous accepted submissions)

**How to negotiate:**
1. Do NOT test the OOS asset (that violates trust)
2. Send a message through the platform: "I noticed asset X is not in scope but appears to be owned by target. Would you like me to include it in my testing?"
3. If they say yes: document the approval in your notes and proceed
4. If they say no: drop it and respect the boundary

**What NOT to do:**
- Never test OOS and then ask for permission retroactively (extortion-adjacent behavior)
- Never submit a finding from an OOS asset and ask them to accept it (it damages your reputation)
- Never pressure a program to expand scope

---

## Mobile App Scope Considerations

When the program includes mobile apps, the scope often extends beyond the app binary:

### What's in Scope (Usually)
- The app binary itself (APK/IPA)
- API endpoints the app communicates with
- Authentication/authorization flows through the app

### What's Out of Scope (Usually)
- The app store listing
- User reviews/comments
- App store infrastructure
- Third-party SDKs embedded in the app

### Mobile-Specific Testing Rules
- You may need to provide the app bundle hash (APK SHA-256, IPA hash) with your report
- Testing on rooted/jailbroken devices is usually allowed, but note it in the report
- SSL pinning bypass is usually expected — document which tool you used (Frida, objection)
- Some programs require you to test against a specific version of the app

---

## Cloud/Infrastructure Scope

Cloud scope is increasingly common:

### What's Usually In Scope
- S3/GCS/Azure Blob buckets owned by the target
- CloudFront/Cloudflare distributions serving target content
- Lambda/Cloud Functions running target code
- The target's cloud configuration (IAM policies, security groups)

### What's Usually Out of Scope
- The cloud provider itself (AWS/Azure/GCP are always OOS)
- Shared infrastructure (CDN edge nodes, cloud provider's internal network)
- Other customers of the same cloud provider

### Cloud-Specific Testing Rules
- DO NOT modify cloud resources (no writing to S3 buckets, no creating IAM users)
- DO NOT attempt to escalate from the target's account to the cloud provider
- Document read-only access carefully: "I was able to LIST bucket contents but did not DOWNLOAD or MODIFY any files"
- If you find credentials (AWS keys, service account JSON), report immediately and DO NOT use them beyond verification

---

## Scope Template for Common Target Types

### Standard Web Application Target

```
In scope: *.target.com, target.com
OOS: Third-party services, acquired companies
Focus: Auth flows, data export, user management
Bounty: P1 $5K, P2 $2K, P3 $500, P4 $200
```

### API-Only Target

```
In scope: api.target.com, docs.api.target.com
OOS: status.target.com, blog.target.com, www.target.com
Focus: Rate limiting on auth, IDOR on user data, SSRF on webhook endpoints
Bounty: P1 $10K, P2 $4K, P3 $1K, P4 $300
```

### Mobile App Target

```
In scope: Android APK (v2.3+), iOS IPA
OOS: Web properties, backend not used by mobile app
Focus: Hardcoded secrets in binary, API auth bypass via mobile, SSL pinning bypass
Bounty: P1 $5K, P2 $2K, P3 $500
```

### Cloud / Infrastructure Target

```
In scope: *.target.com, S3 buckets, AWS accounts listed
OOS: Cloud provider infrastructure, other AWS customers
Focus: S3 bucket policies, IAM roles, exposed Lambda endpoints
Bounty: P1 $7.5K, P2 $3K, P3 $750
```

### DeFi / Smart Contract Target

```
In scope: Contract addresses listed, frontend dApp
OOS: Blockchain infrastructure, third-party oracles
Focus: Reentrancy, access control, oracle manipulation, flash loan attacks
Bounty: P1 $50K+, P2 $20K, P3 $5K
```

---

## Scope Change Monitoring

Programs update their scope. Stay current:

1. **Subscribe to the program's RSS/Atom feed** (if available)
2. **Check the program page before every session** — scope changes are easy to miss
3. **Watch for scope additions** — new assets are often less mature than the rest of the target
4. **Watch for scope removals** — don't accidentally test an OOS asset because you didn't notice it was removed
5. **Track scope versions** in your notes — note the date you last checked scope
