# OPERATOR MINDSET & METHODOLOGY RULES

> A bug bounty hunter's most powerful tool is not a scanner or a proxy — it's the
> space between their ears.

---

## 1. THE HUNTER MINDSET

### The Core Difference

1.1 A pentester asks: "Does this endpoint validate input?" A hunter asks:
"Can I make this endpoint do something the developer never intended?"

1.2 Pentesters report every finding. Hunters triage ruthlessly — if it can't
be chained to impact, it's noise.

1.3 Compliance findings (missing headers, verbose errors) are rarely paid.
Focus on impact: data access, ATO, code execution, privilege escalation.

1.4 The hunter operates with a zero-trust model. Assume every endpoint is
vulnerable until proven otherwise.

1.5 The biggest payouts come from creative exploitation the program never
anticipated.

### Payout Optimization

1.6 Not all bugs are equal. A critical IDOR on a core feature pays more
than ten medium XSS findings.

1.7 Chain construction multiplies payout. Low-severity info disclosure
+ medium SSRF + high ATO = critical payout.

1.8 Timing matters — hunting during program launch, after feature releases,
or during bounty increases yields higher returns.

1.9 Business logic bugs pay more than technical bugs. A reflected XSS is
copy-paste. A flawed subscription downgrade is irreproducible.

### Developer Empathy

1.10 Developers are overworked, under-resourced humans making reasonable
decisions with incomplete information.

1.11 Understanding why a bug exists helps you find more of the same type.
An IDOR exists because the developer trusted the client-provided ID.

1.12 Framework defaults are often insecure by design: Rails mass assignment,
Django DEBUG=True, Express.js body-parser nested objects.

1.13 When you find a bug, trace it back to a shortcut. Find the pattern,
find more bugs.

### Emotional Discipline

1.14 Bug bounty is a game of variance. You can work 40 hours and find
nothing, then find a critical in 10 minutes.

1.15 Do not tie your self-worth to finding bugs. No single bug defines
your career. The best hunters have been rejected hundreds of times.

1.16 The goal of every session is learning. If you learn something new
about the application, the session is a success. Findings are a side effect.

---

## 2. DEVELOPER PSYCHOLOGY

Every vulnerability traces back to a human decision.

### Time Pressure

2.1 Shipping deadlines are the #1 cause of security bugs. Features ship
before review. Debug endpoints ship to production.

2.2 Sprint culture means security is always cut. "We'll add auth later"
means auth is never added properly.

2.3 Endpoints that look hastily added — non-standard naming, missing
validation, inconsistent error handling — were shipped under pressure.
Test them aggressively.

### The Stack Overflow Trap

2.4 The most dangerous code is copied from Stack Overflow. The developer
copied the first answer without understanding security implications.

2.5 Classic SO bugs: SQL concatenation, XML parsing without XXE protection,
deserialization without type validation, file ops without path sanitization.

2.6 Any snippet with "security note" or "warning" in the answer was likely
copied without the fix. Transitive dependency vulnerabilities from npm/PyPI
are everywhere.

### Framework Defaults

2.7 Find the framework, find the default vulnerability. Rails: mass_assignment
on by default. Django: DEBUG=True in production, SECRET_KEY in public repos.
Express.js: body-parser accepts nested objects (prototype pollution).
Spring Boot: Actuator endpoints enabled. Laravel: APP_DEBUG=true.
WordPress: plugin CVEs, XML-RPC enabled.

### Forgotten Debug Endpoints

2.8 Every app has debug endpoints supposed to be removed. They often bypass
auth and return excessive data. Common: /debug, /test, /admin/dev, /api/echo,
/healthz, /status, /info, /version, /sandbox.

2.9 "Authenticated but not authorized" debug endpoints — any user can
access them if they know the path.

### Incomplete Migrations

2.10 During auth migration, old systems with weaker security remain active.
API versioning creates gaps (v1 endpoints with weaker auth alongside v2).
Database migrations leave old columns with sensitive data.

### Legacy Code

2.11 Code written 5+ years ago was written in a different security landscape.
Legacy endpoints lack rate limiting, input validation, authorization checks.
/api/v1/ is a goldmine.

### Ship Now, Fix Later

2.12 "We'll add authorization later" = never added. "We'll validate that
input later" = passed unsanitized. "We'll add logging after launch" = no
audit trail.

### Developer Communication Clues

2.13 API docs saying "admin only" likely check client-side only. Fields
named isAdmin returning false can often be set to true.

2.14 "User not found" vs "Wrong password" = user enumeration. Rate-limited
password reset = they know it matters. Non-rate-limited IDOR = they didn't
think of it.

---

## 3. ANOMALY DETECTION

Train yourself to notice tiny deviations from expected patterns.

### Response Size

3.1 Compare response sizes across similar requests — different parameters,
methods, auth states. Larger than expected = extra data. Zero-byte on some
inputs but not others = hidden logic = IDOR primitive.

### Timing

3.2 Response time differences reveal database queries. If admin takes 300ms
and nonexistent takes 30ms, timing-based enumeration is possible.

3.3 Consistent 200ms+ difference on conditionals = SQLi vector. Race
windows estimated by response timing.

### Error Messages

3.4 "User not found" vs "Incorrect password" = user enumeration.
Full stack traces = debug mode in production (chainable to RCE).

3.5 Errors containing SQL = SQLi likely. Errors with file paths = path
traversal. XML error on JSON endpoint = test XXE. JSON error on XML =
test prototype pollution.

3.6 "Authentication required" vs "Forbidden" vs "Not Found" reveals which
endpoints exist vs require auth vs forbid.

### Status Codes

3.7 200 when expecting 401 = no auth (most valuable status code). 200 when
expecting 404 = endpoint exists. 500 on unusual input = unhandled case =
potential vulnerability.

### Extra Data

3.8 Undocumented JSON fields = attack surface. isAdmin: false = try
isAdmin: true (mass assignment). Sequential DB IDs = weak entropy = IDOR.
HTML comments like `<!-- TODO: add auth -->` mean no auth.

### Input Reflection

3.9 Input reflected unencoded = XSS. In headers = header injection. In URL
redirect = open redirect. In error = potential SSTI. In filename = path
traversal.

### Behavioral Anomalies

3.10 Rate limiting on some endpoints but not others = hit the unprotected
ones harder. Cache behavior differing by auth = CDN may serve privileged
responses to unauth users.

---

## 4. WHAT-IF EXPERIMENTS

For every endpoint, ask: "What if I do X instead of what was expected?"

### Auth & Access

4.1 What if I remove the Authorization header? Send an expired token or a
token from another user? Change JWT algorithm to "none"? Use HS256 when
server expects RS256 (key confusion)? Change GET to POST/PUT/DELETE?

4.2 What if I add X-Forwarded-For: 127.0.0.1? X-Original-URL: /admin?

### IDOR

4.3 What if I change the user ID by +/-1? Encode differently (Base64, hex)?
Use negative integers, zero, very large integers? String IDs like "admin",
"me"? Array syntax (`id[]=1&id[]=2`)? Comma-separated?

### Input Validation

4.4 What if I send a string instead of number, array instead of object,
null/NaN, empty string, unicode, 10,000+ characters?

### Business Logic

4.5 What if I perform operations in reverse order? Repeat an operation?
Skip steps? Modify quantities, prices, discount codes? Use negative
quantities? Set price to 0?

### State & Race Conditions

4.6 What if I send the same request twice? 100 times quickly? Concurrent
requests during a state change (TOCTOU)? Pause mid-flow? Replay from a
previous session?

### File Upload

4.7 What if I upload a file with double extension (file.jpg.php), .htaccess,
zip archive, spoofed magic bytes, SVG with embedded scripts, path traversal
in the filename?

### Headers & SSRF

4.8 What if I use XML Content-Type on JSON endpoint? Send mismatched Host
header (host header injection)? Duplicate headers?

4.9 What if I replace a URL with http://127.0.0.1, http://169.254.169.254/
latest/meta-data/, file:///etc/passwd, gopher://? Use URL encoding bypass?
IPv6 localhost [::1]? Alternative IPs (0.0.0.0, 127.1)?

### GraphQL & Rate Limiting

4.10 What if I introspect the schema? Use aliases to bypass rate limits?
Send deeply nested queries? Bypass rate limits via X-Forwarded-For, IPv6,
HTTP/2 multiplexing?

---

## 5. TIME MANAGEMENT

### The 20-Minute Rule

5.1 If 20 minutes on an endpoint yields nothing interesting, rotate to a
completely different endpoint. Prevents tunnel vision.

5.2 Exception: strong signals (timing diff, error message, undocumented
endpoint) deserve follow-through.

5.3 If you don't know how long you've been on something, you've been on it
too long.

### Focus Blocks

5.4 90-minute focus blocks with 15-20 minute breaks. One objective per block.
No notifications. Morning for high-cognitive work, afternoons for fuzzing/recon.

5.5 After 3 blocks (4.5 hours), stop. Diminishing returns are severe.

### Energy & Stopping

5.6 Morning is hunting time, not admin time. Sleep 8 hours. Light,
protein-rich meals. Caffeine 30 min before a block, not continuously.

5.7 Stop when you find a bug — document before continuing. Stop when tired
or frustrated. Stop when you've completed your objective.

---

## 6. TARGET SELECTION

### Program Maturity

6.1 New (<3 months): high finding rate, high duplication. Established (1-3
years): harder bugs, less duplication. Mature (3+): deep — race conditions,
chains, business logic.

6.2 Frequent payouts = actively triaging. No disclosures in 6+ months =
may have stopped.

### Bounty vs Surface

6.3 High bounty + small surface = over-subscribed. Low bounty + large
surface = under-subscribed. Medium + massive = sweet spot.

6.4 Bounty floors matter more than ceilings. Read 30-50 disclosed reports
before testing. Patterns reveal weak spots.

### Known vs New

6.5 70% time on known stacks, 30% on new stacks (learning investment).

---

## 7. TARGET SWITCHING DISCIPLINE

### When to Abandon

7.1 All surface exhausted. Program non-responsive (30+ days). Consistent
N/As. Target is a wall (20+ hours, zero findings). Better opportunity
appears.

### When to Persist

7.2 Strong signals found. New features spotted. Tech stack matches past
success. Recent scope addition. One bug reveals a pattern.

### Sunk Cost

7.3 "I've spent 30 hours" is not a reason to continue. The question: will
the next 30 hours produce better results here or elsewhere?

7.4 Keep a target journal. Note what you tested and what signals remain.
Come back in 3 months.

### Cadence

7.5 First session: 4 hours max. After first finding: invest more. After 3
findings: diminishing returns. Monthly rotation. Quarterly deep dives.

---

## 8. REJECTION RESILIENCE

8.1 Average acceptance rate is 20-30%. 70-80% rejection is normal.

8.2 Even top earners have 50%+ rejection. The difference is total volume.

8.3 Rejection is data. Each one should lead to one methodology improvement.
Keep a rejection log.

8.4 Submit dispassionately — the report is a data point, not your child.

8.5 After rejection, submit again quickly. The 100th rejection hurts less.
Keep submitting.

---

## 9. INFORMATION ASYMMETRY

9.1 Read every disclosed report for a program before testing. Reveals what
they pay for, what they reject, endpoint naming patterns.

9.2 If accepted reports mention /api/v2/users/{id}, there's likely a less-
secure /api/v1/ version.

9.3 Monitor changelogs — new endpoints, deprecated endpoints still working.
Public GitHub repos: commit messages mentioning "fix", "security", "auth".

9.4 Monitor CT logs for new subdomains. Job postings reveal tech stacks.
Third-party integrations with known vulns are testing targets.

---

## 10. THE HUNTER'S EDGE

### Deeper Testing

10.1 Average hunter tests IDOR by changing user IDs in URL. Top hunter
tests IDOR in WebSocket messages, API response fields, filenames, error
messages, exports, batch ops, cached responses.

10.2 The difference between medium and critical is impact demonstration.
"Reflected XSS on admin panel" > "Reflected XSS."

### Chain Construction

10.3 Chaining two lows into a high is the most valuable skill. Common
chains: info disclosure + IDOR = account compromise; SSRF + internal
service = RCE; open redirect + OAuth = token theft.

10.4 A chain is only as strong as its weakest link. Prove every step.

### Under-Tested Classes

10.5 Business logic, race conditions, prototype pollution, JWT attacks,
HTTP smuggling, XXE, SSTI, cache poisoning, mass assignment are under-
tested. Most hunters test XSS, SQLi, CSRF. That's your advantage.

### Code Reading & Business Context

10.6 Code reading is exponentially more effective. Search for TODO/FIXME,
API keys, routes without auth middleware, SQL concatenation.

10.7 Understand what the business values. E-commerce = revenue bugs.
Social = trust bugs (ATO). Healthcare = data isolation.

---

## 11. COMPETITION AWARENESS

11.1 Check disclosure feeds. If three IDORs were accepted last week, move
to a different class. If no GraphQL reports on a GraphQL program, that's
your opening.

11.2 Automated bug classes (XSS, SQLi, CSRF, open redirect) are saturated.
Focus on what scanners miss: business logic, race conditions, auth logic.

11.3 Hunt when others aren't: weekends, holidays, timezone-shifted. Wait
72 hours after feature launches. Fuzz undocumented endpoints. Test mobile
API endpoints.

---

## 12. RISK MANAGEMENT

12.1 Never use destructive payloads. Read-only first. Modify only your
own test data.

12.2 SSRF: use services you control. RCE: benign commands (sleep, id).
Race conditions: limit concurrency to 50.

12.3 Respect rate limits. Randomize timing. Use legitimate user agents.
Use test accounts, not real users.

12.4 Staging has weaker security but is less valuable. If a bug exists in
staging, check production. Report the production bug.

12.5 Do not exfiltrate more than necessary. Three records proves the point.
10,000 is a data breach. Redact PII.

12.6 Scope documents are legal agreements. No social engineering, physical
security, or DoS testing. Use VPN, burner emails, unique usernames. 2FA
everything.

---

## 13. LEARNING INVESTMENT

13.1 Allocate 10-20% of hunting time to learning. Learning compounds.

13.2 Each new tech stack opens new programs. Focus on auth mechanisms,
common misconfigs, known vulnerabilities.

13.3 You don't need 100 hours. 5-10 hours makes you productive in a new
class. The investment repays itself within weeks.

13.4 Master one tool at a time. Terminal proficiency: invest in shell
scripting, grep, sed, awk, jq.

---

## 14. SESSION PLANNING

14.1 Review target notes. Set a specific, bounded objective. Prepare tools
before starting. Set a timer.

14.2 Output-oriented goals only ("test 20 endpoints"). You control output,
not outcome.

14.3 Phase 1 (0-15min): Review. Phase 2 (15-90min): Execute. Phase 3
(90-110min): Document. Phase 4 (110-120min): Review.

14.4 Write session summary: what tested, found, signals remaining, what
to change. Continuous improvement: Plan → Do → Check → Act.

---

## 15. OSINT MINDSET

Everything the application does is data. Every response tells a story.

15.1 URL patterns reveal API versions, resource nesting, microservice
boundaries. Undocumented parameters = feature flags.

15.2 Error messages reveal the stack (MySQL/PG/SQLite, Node/Python/Java,
Symfony/Laravel/Django/Rails).

15.3 Server header reveals version. X-Powered-By reveals technology.
Missing CSP/HSTS/X-Frame-Options reveal gaps.

15.4 HTML comments reveal TODOs. Hidden form fields are manipulable.
JS variables contain endpoints, internal IPs, feature flags, API keys.

15.5 CNAME records reveal cloud services. MX reveals email provider.
Missing SPF = email spoofing. CNAME to unregistered service = subdomain
takeover.

15.6 Login page reveals auth provider (custom = more flaws). Password
policies reveal maturity. MFA options reveal security posture.

---

## 16. THEORY OF CONSTRAINTS

16.1 Identify your bottleneck. Common constraints: recon depth, tool
availability, account access, bug class knowledge, target selection,
writing efficiency, time management, persistence, chain construction.

16.2 "What limited my last 10 sessions?" If you fuzzed 20 hours and found
nothing = recon depth or target selection. Found bugs but didn't submit =
writing efficiency.

16.3 Fix one constraint at a time. Dedicate a week. The investment pays
for itself in every future session. Beginner = bug class knowledge.
Intermediate = target selection. Advanced = chain construction.

---

## 17. MENTAL MODELS

### Developer Shortcuts

17.1 Every shortcut creates a vulnerability: "I'll just trust the client"
= mass assignment/IDOR. "I'll return the whole object" = data leakage.
"Make it work, add auth later" = unprotected access. "Default config"
= insecure defaults.

### Unexpected Input & Boundaries

17.2 Applications break on input never considered: wrong type/format,
extreme/empty values, unicode, encoding variations, concurrent requests.

17.3 Bugs cluster at boundaries: auth/nonauth, admin/user, v1/v2, staging/
prod, public/private. Test edges, not core.

### Trust, Legacy & Feature Flags

17.4 Find what the app trusts without verification: client IDs (IDOR),
prices (manipulation), internal IPs (SSRF), JWTs, cached data.

17.5 Old code has old vulnerabilities. /api/v1/ paths, PHP/ASP frameworks,
different auth per section = test aggressively.

17.6 Hidden features behind flags have security gaps. Detect via JS
booleans, URL params, headers, cookies, undocumented fields.

### State, Defaults & Race Conditions

17.7 Applications are state machines. Map states, test invalid transitions.

17.8 Default configurations optimize for ease of use, not security. Check
default passwords, paths, ports.

17.9 Any read-transform-write operation can race. Check-then-act, first-
write-wins, delete-then-create are common patterns.

---

## 18. EVIDENCE-FIRST MINDSET

18.1 Capture the moment you see something interesting. You will forget the
exact request, response, and context.

18.2 For every finding: full request, full response, timestamp, endpoint,
auth state, app state.

18.3 Organize by target and date. Label screenshots descriptively. Maintain
a running session document.

18.4 Evidence cannot be recreated — rate limiting, resource deletion, app
changes, ephemeral session state. The more chain steps, the harder to
reproduce.

18.5 A finding without evidence is a claim. The triager won't reproduce it.
Your evidence must tell the story from start to finish.

---

## 19. HUNTING IN THE DARK

### Public Surface

19.1 Public endpoints are deeper than most realize. Test: search (SQLi, XSS),
contact forms (SSRF), password reset (enumeration, token prediction),
registration (mass assignment), error pages (stack traces), sitemap.xml,
/.well-known/.

### JS Bundles

19.2 JS bundles are the richest source of endpoint info. Search for API
URLs, internal domains, API keys, admin routes, feature flags, debug
functions. Check for .map files — original source with comments.

### Wayback & Misconfigs

19.3 Historical endpoints may still work. Historical API responses may
contain still-valid keys.

19.4 Scan for open S3 buckets, Firebase, Elasticsearch, Grafana, Jenkins,
exposed .git/config and .env. A single misconfiguration can be career-
defining.

19.5 Default credentials on admin panels, Swagger, Jenkins, phpMyAdmin
remain common and accepted.

### Unauthenticated Chains

19.6 Every public vulnerability is a foothold. XSS → steal cookies → ATO.
SSRF → cloud metadata → credentials → internal pivot. Host header injection
→ password reset redirect → ATO. The foothold is not the finding. The chain
is.

---

## 20. GROWTH MINDSET

20.1 Write a post-mortem for every finding: what, how, what learned, what
to change. After 100 findings, 100 pages of accumulated wisdom.

20.2 Pattern recognition is hunt memory. Keep a notebook of associations.
"Target A (Rails) had mass assignment. Target B (Node) had mass assignment
with update_attributes equivalent."

20.3 Monthly reflection: review findings, rejections, learning goals.
Quarterly audit: check for untested classes, new techniques.

20.4 Teaching reveals gaps. Share techniques and failures. The goal is
being better than you were last month.

20.5 Bug bounty is a marathon. Burnout is #1 reason hunters quit.
Sustainable hunting means days off without guilt. Learning from failures
without despair.

20.6 The best hunters are the ones still hunting 5 years later. Consistency
beats intensity. Your skills compound with every target, every technique,
every session. Keep hunting.

---

## FINAL WORDS

These rules are not to be memorized — they are habits to be internalized.

Read this document. Apply the principles. Review your sessions against these
rules. Update your methodology. And most importantly: keep hunting.

The bugs are out there. They're waiting for the hunter who thinks differently.
Be that hunter.

---

*"The best bug bounty hunters don't find vulnerabilities — they create
conditions where vulnerabilities reveal themselves."*

---

**Document version:** 1.0
**Last updated:** June 2026
**Author:** Jiggy Methodology
