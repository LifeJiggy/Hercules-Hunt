# OPERATOR MINDSET & METHODOLOGY RULES

> A bug bounty hunter's most powerful tool is not a scanner or a proxy — it's the
> space between their ears. This document encodes the psychological framework,
> strategic thinking, and operational discipline that separates top earners from
> everyone else.

---

## 1. THE HUNTER MINDSET

Bug bounty hunting is fundamentally different from penetration testing. A pentest
checks boxes against a compliance checklist. Bug bounty hunting hunts for impact.

### The Core Difference

1.1 A pentester asks: "Does this endpoint validate input?" A hunter asks: "Can I
make this endpoint do something the developer never intended?"

1.2 Pentesters report every finding. Hunters triage ruthlessly — if it can't be
chained to impact, it's noise.

1.3 Compliance findings (missing headers, verbose error messages, minor version
disclosure) are rarely paid in bounty hunting. Focus on impact: data access,
account takeover, code execution, privilege escalation.

1.4 The hunter operates with a zero-trust model for every application. Assume
every endpoint is vulnerable until proven otherwise.

1.5 Pentesters are bound by scope documents. Hunters push boundaries within
program rules — the biggest payouts come from creative exploitation the program
never anticipated.

### Payout Optimization

1.6 Not all bugs are created equal. A critical IDOR on a core feature pays more
than ten medium XSS findings on minor endpoints.

1.7 Chain construction multiplies payout. A low-severity information disclosure
chained to a medium SSRF chained to a high account takeover = critical payout.

1.8 Understand the program's payout curve. Some programs pay linear. Some have
bonuses for criticals. Some cap per-finding. Some have variable pay based on
user data sensitivity.

1.9 Timing matters. Hunting during program launch, after feature releases, or
when programs announce increased bounties yields higher returns per hour.

1.10 Duplicate detection is a skill. The first 24-48 hours after a feature
launch have the lowest duplication risk. After that, assume others have found
the low-hanging fruit.

### Creative Exploitation

1.11 The obvious bug is usually already reported. The gold is one level deeper
— the second-order effect, the chain primitive, the race condition window.

1.12 Every feature has an implicit trust boundary. Find it. Cross it.

1.13 Business logic bugs pay more than technical bugs because they're unique to
the application. A reflected XSS is copy-paste. A flawed subscription downgrade
flow is irreproducible.

1.14 The application tells you what it values. Login pages say "auth is
important." Payment flows say "money is important." Admin panels say
"privilege is important." Test what the application values most.

1.15 Users will do things developers never expected. Multi-account usage,
incognito windows, concurrent sessions, shared devices, copy-paste of tokens,
bookmarking partial states. If users can do it, test it.

### Developer Empathy

1.16 Developers are not your enemy. They are overworked, under-resourced humans
making reasonable decisions with incomplete information.

1.17 Understanding why a bug exists helps you find more of the same type. An
IDOR exists because the developer trusted the client-provided ID. A rate
limiting gap exists because the developer didn't anticipate automated access.

1.18 The developer's mental model of "how this feature works" is always
simpler than reality. Edge cases, race conditions, concurrent access, and
unexpected input sequences violate that model.

1.19 Framework defaults are often insecure by design. Rails mass assignment,
Django DEBUG=True inherited from template projects, Express.js with
body-parser accepting nested objects — these are features that become
vulnerabilities.

1.20 When you find a bug, you can almost always trace it back to a shortcut the
developer took. Find the shortcut pattern, find more bugs.

### Emotional Discipline

1.21 Bug bounty is a game of variance. You can work 40 hours and find nothing,
then find a critical in 10 minutes. The work is not linearly correlated with
results.

1.22 Do not tie your self-worth to finding bugs. You are a hunter. Some days
the prey is invisible. Some days it walks into your trap.

1.23 Celebrate other hunters' success. The bounty pool is not zero-sum. Other
people's findings validate the ecosystem and attract more programs.

1.24 No single bug defines your career. The best hunters have been rejected
hundreds of times. They kept going.

1.25 The goal of every session is learning, not finding. If you learn something
new about the application, the session is a success. Findings are a side effect.

---

## 2. DEVELOPER PSYCHOLOGY

Understanding why developers make security mistakes is the single highest-leverage
investment a hunter can make. Every vulnerability traces back to a human decision.

### Time Pressure

2.1 Shipping deadlines are the #1 cause of security bugs. Features ship before
security review. Debug endpoints ship to production. Input validation is
deferred to "the next sprint" that never comes.

2.2 The developer had 48 hours to implement a feature that should have taken
two weeks. They copy-pasted the first Stack Overflow answer that worked.

2.3 Sprint culture means security is always the thing that gets cut when time
runs low. "We'll add auth later" means auth is never added properly.

2.4 Hotfixes bypass all security review. A bug that was patched at 2 AM to
fix a production outage likely introduced two more vulnerabilities.

2.5 When you see an endpoint that looks hastily added — non-standard naming,
missing parameter validation, inconsistent error handling — test it aggressively.
It was shipped under pressure.

### The Stack Overflow Trap

2.6 The most dangerous code in any application is code copied from Stack
Overflow. The developer copied the first answer without understanding the
security implications.

2.7 Classic SO copy-paste bugs: SQL queries built with string concatenation,
XML parsing without XXE protection, deserialization without type validation,
file operations without path sanitization.

2.8 Stack Overflow answers from 2010-2015 are especially dangerous. They
predate common security awareness around deserialization, SSRF, and
prototype pollution.

2.9 Any code snippet that includes "security note" or "warning" in the
Stack Overflow answer is likely copied without the security fix attached.

2.10 The npm/PyPI/Gem equivalent: developers install packages without auditing
dependencies. Transitive dependency vulnerabilities are everywhere.

### Framework Defaults

2.11 Every framework has insecure defaults that developers never change. Find
the framework, find the default vulnerability.

2.12 Rails: `mass_assignment` was on by default for years. `protect_from_forgery`
is on by default but has bypasses. `config.force_ssl` is often not set.

2.13 Django: `DEBUG=True` in production is common in inherited projects.
`SECRET_KEY` is in settings files pushed to public repos. `ALLOWED_HOSTS` is
often `['*']`.

2.14 Express.js: `body-parser` accepts nested objects by default, enabling
prototype pollution. `express-session` defaults to in-memory storage.

2.15 Spring Boot: Actuator endpoints are enabled by default. `/actuator/env`
discloses environment variables including secrets. `/actuator/beans` maps
the entire application.

2.16 Laravel: `APP_DEBUG=true` in production. `.env` file accessible via
misconfigured web root. Mass assignment via `$fillable` inversion.

2.17 Wordpress: Thousands of plugins with known vulnerabilities. Outdated core.
Default admin paths. XML-RPC enabled by default for years.

2.18 The framework tells you what to test. Research framework defaults before
touching any endpoint.

### Forgotten Debug Endpoints

2.19 Every application has debug endpoints that were supposed to be removed.
They were documented in the developer's local notes and never cleaned up.

2.20 Common debug endpoint names: `/debug`, `/test`, `/admin/dev`, `/api/echo`,
`/healthz`, `/status`, `/info`, `/version`, `/api-test`, `/sandbox`,
`/dev/null`, `/staging-test`.

2.21 Debug endpoints often bypass authentication. They were created for local
development where there is no auth.

2.22 Debug endpoints often return excessive data: full database rows, stack
traces, environment variables, internal IP addresses, database connection
strings.

2.23 Fuzz for debug endpoints with a wordlist of 500+ common debug paths.
Half the battle is just knowing what names developers choose.

2.24 Debug endpoints that are "authenticated but not authorized" — any user
can access them if they know the path, and they don't check permissions, only
login status.

### Incomplete Migrations

2.25 Applications evolve. Code is migrated from monolith to microservice. Auth
is migrated from session tokens to JWTs. Database migrations leave old columns.

2.26 During authentication migration, there is a window where both old and new
systems accept credentials. The old system often has weaker security.

2.27 API versioning creates security gaps. v1 endpoints with weaker auth are
left running alongside v2 endpoints with proper auth.

2.28 Database migrations leave old columns populated with sensitive data even
though the UI no longer displays them. If you can access the raw API response,
you can find deleted fields.

2.29 Feature flag migrations: the new feature is behind a flag, but the old
endpoint is still accessible. The old endpoint has the vulnerability the new
feature fixed.

2.30 Cloud migrations: on-prem logic replicated to cloud with different
security assumptions. On-prem trusted internal IPs. Cloud has no internal
network boundary.

### Legacy Code

2.31 Code written 5+ years ago was written in a different security landscape.
CSRF was not well understood. SQL injection was mitigated with "magic quotes."
File upload validation was minimal.

2.32 Legacy endpoints use legacy patterns. If you find an endpoint with
`?id=123` style parameters and no auth, test it immediately.

2.33 Legacy code often lacks rate limiting, proper logging, input validation,
and authorization checks. The newer code learned from the old code's mistakes.
The old code still runs.

2.34 Legacy authentication mechanisms (HTTP Basic Auth, session cookies without
HttpOnly/Secure flags, token-based auth stored in URLs) persist alongside modern
auth.

2.35 Legacy API versions (`/api/v1/`) are a goldmine. They have fewer security
controls and are less monitored than `/api/v3/`.

### The "Ship Now, Fix Later" Mentality

2.36 Every startup ships features with known security gaps because "we can fix
it before we go to production" — and production is always the next deployment.

2.37 "We'll add authorization later" means authorization was never added. The
endpoint exists and works without checking who is calling it.

2.38 "We'll validate that input later" means the input is passed unsanitized
to database queries, file operations, and template engines.

2.39 "We'll remove this feature flag before launch" means the feature flag
is still there, and someone discovered they can enable it by sending
`X-Feature-Enabled: true`.

2.40 "We'll add logging after launch" means there is no audit trail. You can
exploit the endpoint without detection.

### Developer Communication Clues

2.41 API documentation reveals developer assumptions. If docs say "this
endpoint is only for admin users," the endpoint likely checks for admin status
client-side only.

2.42 Comments in API responses reveal developer intent. A field named `isAdmin`
that is always `false` in responses suggests it can be `true` if you send it.

2.43 Error messages that distinguish between "user not found" and "wrong
password" reveal the developer's concern about usability over security.

2.44 Naming conventions reveal architecture. `getUserData_insecure` suggests
there is also a `getUserData_secure` endpoint. `temp_token` suggests
permanence was not considered.

2.45 The presence of rate limiting reveals what developers think is valuable.
Rate-limited password reset = they know it's a target. Non-rate-limited
IDOR = they didn't think of it.

---

## 3. ANOMALY DETECTION

The best hunters notice things that look "off" — tiny deviations from expected
patterns that signal a vulnerability. Train yourself to see anomalies everywhere.

### Response Size Anomalies

3.1 A response that is larger than expected may contain extra data. A user
profile endpoint returning 2KB for user 1 and 15KB for user 2 suggests user 2
has admin data in their response.

3.2 A response that is smaller than expected may indicate an error path
revealed information. A 200 with empty body when expecting JSON suggests
the endpoint processed input differently.

3.3 Compare response sizes across similar requests. Same endpoint, different
parameters. Same endpoint, different methods. Same endpoint, authenticated vs
unauthenticated.

3.4 Zero-byte responses on some inputs but not others reveal hidden logic.
If `/api/file/1` returns 200 with data but `/api/file/999` returns 200 with
nothing, the application is accepting any ID but only returning data for valid
ones. This is an IDOR primitive.

3.5 Response size changes after authentication reveal what endpoints gate
versus what endpoints just hide UI. A large unauthenticated response that
shrinks after auth means data was returned without authorization checks.

### Timing Anomalies

3.6 Response time differences reveal database queries. If `user=admin` takes
300ms and `user=nonexistent` takes 30ms, timing-based user enumeration is
possible.

3.7 Response time differences based on parameter presence reveal validation
logic. If adding `?debug=true` adds 5 seconds, something special is happening
on the server.

3.8 Time-based blind injection: if `id=1` takes 50ms and `id=1 AND 1=1` takes
50ms, but `id=1 AND 1=2` takes 50ms, timing injection is likely not viable.
If there's a consistent 200ms difference, you have a vector.

3.9 Race condition windows can be estimated by response timing. An endpoint
that takes 100ms has a smaller race window than one taking 2000ms.

3.10 Static assets served faster than dynamic content: baseline. Dynamic
content with inconsistent timing across similar requests suggests load
balancing or caching. Inconsistent timing on POST requests suggests database
write contention.

### Error Message Variations

3.11 Different error messages for different failure modes reveal server logic.

3.12 "User not found" vs "Incorrect password" = user enumeration vulnerability.
The developer chose usability over security.

3.13 "Invalid input" vs "Invalid input at position 5" = input validation
details exposed. Fuzz the validation boundary.

3.14 Full stack traces = debug mode enabled in production. This is often
chainable to RCE if the stack trace reveals code paths.

3.15 Error messages containing SQL = SQL injection may be possible with
different inputs. The developer caught this error but not all.

3.16 Error messages containing file paths = path traversal or LFI possible.
The developer exposed include paths.

3.17 Error messages in different languages = localization issue. The developer
did not handle all locales for error messages. Unicode handling may be buggy.

3.18 XML parsing error on JSON endpoint = the endpoint accepts XML too.
Test XXE.

3.19 JSON parsing error on XML endpoint = the endpoint accepts JSON too.
Test prototype pollution.

3.20 "Authentication required" vs "Forbidden" vs "Not Found" for different
endpoints reveal which endpoints exist vs which require auth vs which
forbid access. 403 vs 404 distinction is especially useful.

### Status Code Surprises

3.21 200 OK when you expect 401 = no auth required. This is the most valuable
status code in bug bounty.

3.22 200 OK when you expect 404 = endpoint exists even if the UI hides it.

3.23 302 redirect when you expect 200 = the logic flow has changed. Follow the
redirect and check if auth is maintained.

3.24 301 redirect when you expect 404 = the endpoint has been moved, not removed.
The old (probably insecure) endpoint may still work.

3.25 400 Bad Request explains what validation the server applies. Fuzz the
boundaries — what is the server checking?

3.26 413 Payload Too Large = file upload without size limit awareness. The
server rejects at proxy level, not application level.

3.27 429 Too Many Requests = rate limiting is present. Test if rate limiting
is per-IP, per-user, per-endpoint, or per-session.

3.28 500 Internal Server Error on unusual input = the developer didn't handle
this case. Every 500 is a potential vulnerability.

3.29 503 Service Unavailable = rate limiting or server protection. Test what
triggers it and how long the cooldown is. Some rate limiters have bypasses.

3.30 WebSocket upgrade status codes: 101 Switching Protocols means the
connection is upgraded. Check if WebSocket auth is validated separately from
HTTP auth.

### Missing Headers

3.31 No Content-Type header in response = the server may return raw data that
could be interpreted incorrectly. CSRF token in URL parameter?

3.32 No Content-Security-Policy header = XSS has wider impact. Data exfiltration
is possible.

3.33 No X-Frame-Options header = clickjacking is possible.

3.34 No X-Content-Type-Options: nosniff = MIME sniffing attacks possible.

3.35 No Set-Cookie on login = session is handled differently. Token in response
body? Check for JWT or API key in response.

3.36 No WWW-Authenticate header on protected endpoints = the auth mechanism
is custom, not standard. Custom auth often has flaws.

3.37 No Vary header on cached responses = cache poisoning possible. The CDN
doesn't differentiate requests by header values.

3.38 No X-Request-Id or similar tracing header = logging is minimal. Less
detection capability.

3.39 Missing CORS headers when expected = the endpoint doesn't support CORS
at all. Try with different origin to confirm.

3.40 Server header revealing exact version (Apache/2.2.15) = outdated software
with known CVEs.

### Extra Data in Responses

3.41 JSON responses with undocumented fields = API returns more than the UI
uses. Every undocumented field is an attack surface.

3.42 `isAdmin: false` in a user profile response = try sending `isAdmin: true`
in a PUT request (mass assignment).

3.43 `role: "user"` in a JWT payload = decode the JWT, modify the role, re-encode
with alg:none or a weak secret.

3.44 `createdAt`, `updatedAt`, `deletedAt` in responses = soft delete is
implemented. The developer may have forgot to filter deleted items.

3.45 `internal_notes` or `admin_notes` fields in responses = the API leaks
internal data intended for admin review.

3.46 Email addresses in unexpected responses = PII leak. Check friend/follower
lists, group members, shared resources, and error responses.

3.47 API keys or tokens in responses = credential leak. Check forgotten
password endpoints, account creation, and profile APIs.

3.48 Database IDs vs UUIDs in responses = sequential IDs indicate weak
entropy and potential IDOR.

3.49 Pagination metadata with total count = if total count differs by auth
status, the endpoint reveals hidden resources exist even if they don't
return them.

3.50 HTML comments in API responses = `<!-- TODO: add auth -->` means no auth.

### Input Reflection Anomalies

3.51 Input reflected in response without encoding = XSS. Test with `><script>`.

3.52 Input reflected in response headers = header injection. Test with newlines.

3.53 Input reflected in JSON response without escaping = JSON injection.
Test with quotes and backslashes.

3.54 Input reflected in URL redirect = open redirect. Test with `//evil.com`.

3.55 Input reflected in error message = potential SSTI. Test with `{{7*7}}`.

3.56 Input reflected in filename = path traversal. Test with `../../../etc/passwd`.

3.57 Input reflected in HTML attribute = attribute-based XSS. Test with `" onfocus=`.

3.58 Input reflected in script tag = DOM-based XSS. Test with `</script>`.

3.59 Input reflected in meta tag = meta refresh XSS or open redirect.
Test with `url=//evil.com`.

3.60 Input reflected in cookie = cookie injection. Test with special characters.

### Behavioral Anomalies

3.61 Session resets after certain actions = the application has different
auth levels. Check if privilege escalation is possible.

3.62 Rate limiting applies to some endpoints but not others = the developer
knows which endpoints are sensitive. Hit the non-rate-limited ones harder.

3.63 CSRF token validation on some forms but not others = the developer added
CSRF protection incrementally. Forms without protection are older or forgotten.

3.64 Cache behavior differs by auth status = the CDN may cache privileged
responses and serve them to unauthenticated users.

3.65 WebSocket connections that persist after logout = the session is not
properly terminated on the server side. Session fixation or reuse possible.

### Response Structure Anomalies

3.66 JSON arrays where you expect objects = schema change. Different
endpoint versions return different structures.

3.67 Nested objects where you expect flat response = data model leaked.
Look for references to other endpoints or resources.

3.68 Null values for non-nullable fields = the backend is returning a
partial object. Error condition leaked.

3.69 Duplicate keys in JSON objects = parser behavior differs by
implementation. Some parsers take the first value, some the last.

3.70 Non-standard encoding (UTF-7, UTF-16, etc.) = the server may handle
character encoding inconsistently leading to filter bypasses.

---

## 4. WHAT-IF EXPERIMENTS

The single most powerful hunting technique is asking "What if I do X instead of
what the developer expected?" For every endpoint, run experiments.

### Authentication & Authorization What-Ifs

4.1 What if I remove the Authorization header entirely?

4.2 What if I send an expired token?

4.3 What if I send a token from another user?

4.4 What if I send a token from another session of the same user?

4.5 What if I change one character in the JWT signature?

4.6 What if I set the JWT algorithm to "none"?

4.7 What if I use `alg: HS256` when the server expects `RS256` (key confusion)?

4.8 What if I add an extra authorization header? Some servers use the first,
some use the last (header smuggling).

4.9 What if I use `Bearer` vs `bearer` vs `Token` vs `token`?

4.10 What if I send the auth token as a query parameter instead of a header?

4.11 What if I send the auth token in the request body?

4.12 What if I send the auth token in a cookie instead of Authorization header?

4.13 What if I access the endpoint from a different IP address?

4.14 What if I access the endpoint from localhost (X-Forwarded-For: 127.0.0.1)?

4.15 What if I change the HTTP method from GET to POST, PUT, DELETE, PATCH?

4.16 What if I try OPTIONS on the endpoint?

4.17 What if I use HTTP/1.0 instead of HTTP/1.1 or HTTP/2?

4.18 What if I send a request without cookies?

### IDOR & Access Control What-Ifs

4.19 What if I change the user ID by +1, -1, or a random UUID?

4.20 What if I encode the ID differently? Base64, hex, MD5 hash?

4.21 What if I use a GUID instead of an integer, or integer instead of GUID?

4.22 What if I use negative integers? -1, -100, 0?

4.23 What if I use very large integers? 999999999, 2147483647, 2147483648?

4.24 What if I use string IDs instead of integers? "admin", "me", "self", "."?

4.25 What if I use array syntax? `id[]=1&id[]=2`?

4.26 What if I use comma-separated values? `id=1,2,3`?

4.27 What if I change the HTTP method on an IDOR endpoint? GET data, try PUT
to modify, DELETE to remove?

4.28 What if I access the resource from a different parent path?
`/api/users/1/posts` -> `/api/admin/posts`?

4.29 What if I use wildcards or pattern syntax? `*`, `%`, `_`?

### Input Validation What-Ifs

4.30 What if I send a string instead of a number?

4.31 What if I send a number instead of a string?

4.32 What if I send an array instead of an object? `value[]=1&value[]=2`

4.33 What if I send an object instead of an array? `value[key]=value`

4.34 What if I send null, undefined, NaN, Infinity?

4.35 What if I send a boolean instead of a string? `true`, `false`

4.36 What if I send an empty string, empty array, empty object?

4.37 What if I send whitespace? `" ", "\t", "\n", "\r\n"`?

4.38 What if I send unicode? null bytes, right-to-left override, homoglyphs?

4.39 What if I send very long input? 1000, 10000, 100000 characters?

4.40 What if I send very short input? 0-length, 1-character?

4.41 What if I send input that matches the serialization format? JSON inside
JSON, XML inside JSON?

### Business Logic What-Ifs

4.42 What if I perform operations in reverse order? (purchase then cancel,
apply coupon then remove item, create account then delete)

4.43 What if I repeat an operation? (submit order twice, click "claim bonus"
multiple times, send same request to password reset)

4.44 What if I skip steps? (go directly to checkout without adding to cart,
navigate to /payment without /review)

4.45 What if I use the same email for two accounts? Can I merge them?

4.46 What if I change my email to someone else's email? Does it send a
verification?

4.47 What if I delete my account? Does it actually delete data or just
soft-delete?

4.48 What if I create an account, change email, then use "forgot password"?
Does it send to old or new email?

4.49 What if I use my account on two devices simultaneously?

4.50 What if I modify a request that was generated by the UI? (change
quantities, prices, discount codes in cart)

4.51 What if I apply a discount after already applying one? (discount stacking)

4.52 What if I use a coupon/coupon code that belongs to another user?

4.53 What if I modify the currency in a payment request?

4.54 What if I use negative quantities in a purchase?

4.55 What if I buy item with price 0? What if I set price to 0?

### State Manipulation What-Ifs

4.56 What if I send the same request twice? (idempotency check bypass)

4.57 What if I send the same request 100 times quickly? (race condition)

4.58 What if I send concurrent requests during a state-changing operation?
(TOCTOU race)

4.59 What if I pause in the middle of a multi-step flow?

4.60 What if I replay a request from a previous session?

4.61 What if I use an old CSRF token with a new session?

4.62 What if I use a CSRF token from one endpoint on another?

4.63 What if I modify a state parameter mid-flow? (status, step, stage, phase)

4.64 What if I refresh the page during an operation?

4.65 What if I click submit twice rapidly?

### File & Upload What-Ifs

4.66 What if I upload a file with a double extension? (file.jpg.php)

4.67 What if I upload a file with no extension?

4.68 What if I upload a .htaccess file?

4.69 What if I upload a symbolic link?

4.70 What if I upload a file that is actually a zip archive?

4.71 What if I upload a file with spoofed magic bytes? (PNG header with PHP code)

4.72 What if I upload an SVG with embedded scripts?

4.73 What if I upload a file with path traversal in the filename?

4.74 What if I change the Content-Type of my upload?

4.75 What if I upload the same file twice?

### Header & Protocol What-Ifs

4.76 What if I add `X-Forwarded-For: 127.0.0.1`?

4.77 What if I add `X-Real-IP: 127.0.0.1`?

4.78 What if I add `X-Original-URL: /admin`?

4.79 What if I add `X-Rewrite-URL: /admin`?

4.80 What if I add `X-HTTP-Method-Override: PUT`?

4.81 What if I add `Content-Type: application/xml` when the endpoint expects JSON?

4.82 What if I add `Accept: text/html` when the endpoint returns JSON?

4.83 What if I add `X-Requested-With: XMLHttpRequest`?

4.84 What if I add `Origin: null` or `Origin: https://evil.com`?

4.85 What if I add `Referer: https://evil.com`?

4.86 What if I send a `Host` header that doesn't match? (host header injection)

4.87 What if I send duplicate headers?

### GraphQL What-Ifs

4.88 What if I introspect the schema? (`__schema` query)

4.89 What if I use aliases to bypass rate limiting?

4.90 What if I send a deeply nested query? (depth-based DoS)

4.91 What if I use fragments to query the same field multiple times?

4.92 What if I use mutations to modify data I shouldn't access?

4.93 What if I use `__typename` to discover hidden types?

4.94 What if I request individual fields to find undocumented fields?

4.95 What if I use batched queries to bypass auth checks?

4.96 What if I use null values for required arguments?

### SSRF What-Ifs

4.97 What if I replace a URL parameter with `http://127.0.0.1:22`?

4.98 What if I replace a URL parameter with `http://169.254.169.254/latest/meta-data/`?

4.99 What if I use DNS rebinding? (change DNS between lookup and connection)

4.100 What if I use `file:///etc/passwd` instead of `http://`?

4.101 What if I use `gopher://` or `dict://` protocols?

4.102 What if I use URL encoding to bypass hostname checks?
`http://127.0.0.1` -> `http://2130706433` (decimal IP)?

4.103 What if I use redirect-based SSRF? (URL redirects to internal)

4.104 What if I use IPv6 localhost? `http://[::1]:22`

4.105 What if I use alternative localhost representations?
`http://0.0.0.0`, `http://127.1`, `http://0x7f000001`?

### Cryptography & Token What-Ifs

4.106 What if I decode the JWT and change the payload?

4.107 What if I decode the JWT and set `iat` to the future?

4.108 What if I decode the JWT and set `exp` to the past?

4.109 What if I decode the JWT and remove signature verification?

4.110 What if I reuse an old password reset token?

4.111 What if I convert the session cookie to uppercase/lowercase?

4.112 What if I base64-decode the session cookie and modify it?

4.113 What if I use a CSRF token from an unauthenticated session?

4.114 What if I use an OAuth code from a different client ID?

### Rate Limiting & Abuse What-Ifs

4.115 What if I bypass rate limiting by adding headers? (X-Forwarded-For)

4.116 What if I bypass rate limiting by using IPv6?

4.117 What if I bypass rate limiting by using HTTP/2 multiplexing?

4.118 What if I bypass rate limiting by spacing requests differently?

4.119 What if I bypass rate limiting by creating multiple accounts?

4.120 What if I bypass rate limiting on password reset by using different IPs?

4.121 What if the rate limit allows 100 requests per minute but not 1000?

---

## 5. TIME MANAGEMENT

Bug bounty hunting is intellectually demanding work. Managing your energy and
focus is as important as managing your tools and targets.

### The 20-Minute Rotation Rule (Expanded)

5.1 If you spend 20 minutes on an endpoint without finding anything interesting,
rotate to another endpoint. Not another test on the same endpoint — a completely
different endpoint.

5.2 The 20-minute rule prevents tunnel vision. The most common hunting mistake
is spending 2 hours trying to exploit a single reflection when the next endpoint
over has an obvious IDOR.

5.3 After 20 minutes, your brain has exhausted the obvious tests. Continuing
has diminishing returns. Fresh endpoints get fresh thinking.

5.4 Exception: if you have found something interesting in the first 20 minutes
(a timing difference, an error message, an unreleased feature), you have
established a "strong signal." Follow signals, not time.

5.5 The 20-minute clock resets when you switch techniques. Move from manual
testing to automated fuzzing to code review. New technique = new clock.

5.6 Track time spent per endpoint. If you don't know how long you've been on
something, you've been on it too long.

### Parkinson's Law for Hunting

5.7 Work expands to fill the time available. If you allocate 8 hours to test
an endpoint, you will find the same results in 8 hours that you could have
found in 2.

5.8 Set artificial time constraints. "I will find a bug in this endpoint within
30 minutes or I move on." The constraint forces efficiency.

5.9 Parkinson's Law applies to entire targets. A target with a $5,000 average
bounty deserves more time than a target with a $500 average bounty. But both
can be tested to exhaustion in 2-3 focused sessions.

5.10 The marginal bug (your 5th finding on the same target) takes 10x the
effort of your 1st. At some point, the next bug is not worth the time.
Switch targets.

### Session Structure: 90-Minute Focus Blocks

5.11 The human brain can maintain deep focus for approximately 90 minutes.
Structure your hunting in 90-minute blocks with 15-20 minute breaks.

5.12 Each 90-minute block should have a single objective: "Fuzz all user
profile endpoints" or "Review JS bundles for API keys" or "Test password
reset flow end-to-end."

5.13 No email, no social media, no notifications during a focus block.
Distraction is the enemy of depth.

5.14 Morning blocks are for high-cognitive tasks (chain construction, code
review, business logic). Afternoon blocks are for lower-cognitive tasks
(fuzzing, recon, documentation).

5.15 The 90-minute block is non-negotiable. If you feel the urge to check
email at minute 45, acknowledge it and continue. The urge passes.

### Break Discipline

5.16 15-minute breaks between blocks are mandatory, not optional. Step away
from the computer. Stand up. Look at something 20 feet away (reduces eye
strain).

5.17 Do not work through breaks to "catch up." You are not behind. The bugs
will still be there.

5.18 Use breaks to reset your mental model. When you come back, you approach
the problem fresh.

5.19 Physical movement during breaks improves cognitive performance for the
next block. Walk, stretch, do pushups. Your brain works better when your
body moves.

5.20 After 3 focus blocks (4.5 hours), stop for the day. Diminishing returns
after that point are severe. More time does not equal more findings after your
brain is fatigued.

### Energy Management

5.21 Morning is hunting time, not admin time. Do not start your day with email,
recon setup, or tool updates. Start with hunting.

5.22 Your peak cognitive hours are a personal resource. Identify yours.
Protect them fiercely.

5.23 Food matters. Heavy meals cause cognitive fatigue. Light, protein-rich
meals sustain focus.

5.24 Sleep is productivity. A hunter who slept 8 hours will find more bugs in
2 hours than a sleep-deprived hunter in 6 hours.

5.25 Caffeine strategy: consume caffeine 30 minutes before a focus block, not
continuously throughout the day. Caffeine crash during a block destroys focus.

### When to Stop

5.26 Stop when you find a bug. Document it. Then decide if you continue or
submit. Do not keep hunting while you have unfiled findings.

5.27 Stop when you're tired. The bug you miss because you're exhausted is not
a bug you would have found "if you had just pushed through."

5.28 Stop when you're frustrated. Frustration leads to rushed testing, missed
evidence, and burn out. Walk away. Come back tomorrow.

5.29 Stop when you've completed your objective for the session. Success is
completing the objective, not finding a bug.

5.30 Stop when the target has nothing left to teach you. If you have exhausted
the attack surface and found nothing, you learned the target is hardened.
That is valuable information, not wasted time.

---

## 6. TARGET SELECTION

Choosing the right target is the highest-leverage decision in bug bounty hunting.
A week on the wrong target is a week of lost opportunity.

### Program Maturity Assessment

6.1 New programs (launched < 3 months ago) have high finding rates but high
duplication rates. The first wave of hunters has picked the low-hanging fruit,
but edge cases remain.

6.2 Established programs (1-3 years old) have been thoroughly tested. The
remaining bugs are harder to find but less duplicated. Chain construction
and business logic bugs are your best bet.

6.3 Mature programs (3+ years) have some of the best hunters testing them
continuously. Surviving bugs are deep: race conditions, complex business logic,
multi-step chains.

6.4 Programs with frequent bounty payouts (check disclosure feed) are actively
triaging and paying. Programs with no disclosed findings in 6+ months may have
stopped triaging.

6.5 Read the program's disclosure timeline. Fast triage (hours to days) = good
program. Slow triage (weeks to months) = risk of burnout.

### Bounty Range vs Attack Surface

6.6 High bounty range + small attack surface = target is over-subscribed.
Every endpoint has been tested by 50 hunters. The remaining bugs are deep.

6.7 Low bounty range + large attack surface = target is under-subscribed.
More surface area per hunter dollar. Higher discovery rate.

6.8 Medium bounty + massive attack surface (think: large SaaS platforms) is
the sweet spot. Enough payout to justify the effort, enough surface that
obvious bugs still exist.

6.9 Bounty floors matter more than ceilings. A program with "$50-$10,000" is
more likely to pay $50 than $10,000. A program with "$500-$5,000" has a higher
minimum.

6.10 Variable bounty programs often pay based on impact, not severity. A
well-documented chain that demonstrates real user impact gets paid more than
a text-book XSS.

### Recent Program Additions

6.11 Programs that recently expanded scope have new, untested surface. Monitor
the program page for scope changes.

6.12 Programs that recently raised bounties signal they want more researcher
attention. The bounty raise is often accompanied by new features.

6.13 Newly acquired companies that join an existing program have different code
bases, different frameworks, and different security postures. The parent
company's security doesn't extend to the acquisition's legacy code.

6.14 Programs that recently added API endpoints (check the changelog or API
docs diff) have fresh attack surface.

6.15 Programs that recently hired a new security team may have different
triaging criteria. The old findings were rejected; the new team may accept them.

### Disclosed Report Analysis for Target Selection

6.16 Read 30-50 recent disclosed reports for any program you're considering.
Understand what the program pays for, what they reject, and what severity
they assign.

6.17 Patterns in rejected reports reveal the program's triage philosophy. If
they reject all self-XSS, don't waste time on self-XSS. If they reject all
content injection without interaction, find non-interaction bugs.

6.18 Patterns in accepted reports reveal the program's weak spots. If 60% of
accepted reports are IDOR, the application has systematic authorization issues.
Go find more IDOR.

6.19 If a program has accepted multiple reports on the same endpoint or same
bug class, the root cause hasn't been fixed. There are more to find.

6.20 Look for gaps in disclosed reports. No GraphQL bugs reported? The program
may have GraphQL surface that hasn't been tested. No business logic bugs?
The business logic is untested.

### Balancing Known Tech Stack vs New Learning

6.21 Hunting targets with frameworks you know (e.g., Rails) has higher
immediate productivity. You understand the common vulnerability patterns.

6.22 Hunting targets with frameworks you don't know has learning value. Every
hour spent hunting is an hour learning a new stack.

6.23 Balance: 70% of your time on known stacks (high productivity), 30% on
new stacks (learning investment).

6.24 When learning a new stack, start with the framework's security
documentation. Know what the framework considers dangerous before hunting.

6.25 The best time to learn a new stack is when a new program launches that
uses it. The learning is motivated by immediate opportunity.

### Signal vs Noise in Program Selection

6.26 Programs that respond to questions in the program feed are actively
managed. Programs that ignore questions may also ignore reports.

6.27 Programs that provide test accounts are more likely to have tested auth
flows. Programs without test accounts may have untested auth — find bugs
before other hunters get access.

6.28 VDP-only (no bounty) programs are training grounds. Use them to build
methodology, not to chase payouts.

6.29 Programs that require extensive setup (VPN, special clients, NDAs) have
higher friction and fewer hunters. The reduced competition may offset the
setup cost.

6.30 Public programs vs private invitations: private programs have fewer
hunters and lower duplication. Build a reputation to get invited.

---

## 7. TARGET SWITCHING DISCIPLINE

Knowing when to switch targets is as important as knowing what to test.
Sunk cost fallacy is the enemy of productivity.

### When to Abandon a Target

7.1 All attack surface exhausted: You have tested every endpoint, every
parameter, every input vector, every auth scenario, every file upload,
every business logic flow. There is nothing new to test.

7.2 The 5-minute kill across all endpoints: For every endpoint in scope, you
spent 5 minutes on basic testing and found nothing interesting. Not a single
anomaly. No timing differences, no error messages, no extra data.

7.3 Program non-responsive: You submitted a legitimate finding and received no
response for 30+ days. The program is not triaging. Move on.

7.4 Scope too limited: The program only allows XSS on a single search page
with a 30-character limit. The scope is designed to prevent meaningful testing.

7.5 Consistent N/As: You've submitted 3+ well-documented, high-quality findings
that were all closed as N/As. The program's triage standards don't match your
methodology.

7.6 Target is a wall: Some applications are genuinely well-secured. If you've
put in 20+ hours with zero findings and zero strong signals, the target is
hardened. Applaud the security team and move on.

7.7 Burnout on target: If the thought of testing the same endpoints again
makes you tired, your brain is telling you something. Listen to it.

7.8 Better opportunity appears: A new program launches with a $50k bounty pool.
Drop what you're doing and pivot. Opportunity cost is real.

### When to Persist

7.9 Strong signals found: You found something odd. A timing difference. An
error message that looks like SQL. An undocumented endpoint. Even if you
haven't exploited it yet, follow the signal.

7.10 New features spotted: You noticed the application has features not
documented in the program scope. New features = new attack surface.

7.11 Tech stack matches past success: The target uses the same framework,
the same cloud provider, the same authentication library you've exploited
before. Your pattern recognition is calibrated for this stack.

7.12 Recent scope addition: The program added new endpoints, new API versions,
or new subdomains. Fresh surface.

7.13 Infrastructure changes: The target migrated from one cloud to another.
Migration periods have security gaps.

7.14 You've found one bug that reveals a pattern: An IDOR on one endpoint
suggests IDOR on similar endpoints. A race condition in one flow suggests
race conditions in other flows. Pattern-revealing bugs are worth following.

7.15 The application is complex enough that multi-step chains are viable:
Complex applications have complex state. Complex state has race conditions,
TOCTOU, and logic flaws.

### The Sunk Cost Fallacy

7.16 "I've already spent 30 hours on this target" is not a reason to continue.
The 30 hours are gone. The question is only: "Will the next 30 hours produce
better results on this target or a different one?"

7.17 Every hour you spend on a target is a commitment to the next hour on that
target. It's easier to stop after 10 hours than after 40.

7.18 The most successful hunters switch targets frequently. They have 5-10
targets in rotation. When one target stalls, they switch to another.

7.19 Keep a target journal. Note what you tested, what you found, and what
signals remain. You can always come back in 3 months when the application
has changed.

### Switching Cadence

7.20 First session on a new target: 4 hours max. If you don't find anything
in the first 4 hours, the bugs are deeper than surface level. Come back later.

7.21 After the first finding on a target: invest more time. You've proven
there are bugs. Follow the pattern.

7.22 After 3 findings on a target: diminishing returns set in. The obvious
bugs are gone. Consider switching unless the findings reveal a deep pattern.

7.23 Monthly rotation: revisit old targets. Applications change. New features
are added. Old bugs get reintroduced during refactors.

7.24 Quarterly deep dive: spend a full day on one target doing deep testing.
Business logic. Chains. Race conditions. Complex state manipulation.

---

## 8. REJECTION RESILIENCE

Bug bounty is one of the few professions where rejection is the default outcome.
Most reports are N/A. Most bugs are duplicates. This is normal, not failure.

### The Statistics of Bug Bounty

8.1 The average accepted report rate across all programs is 20-30%. This means
70-80% of your reports will be rejected or marked as N/A.

8.2 This is not a reflection of your skill. It is the nature of the game.
Programs have specific standards, and you can't know them without submitting.

8.3 Even top earners have a 50%+ rejection rate. The difference between top
earners and everyone else is not rejection rate — it's total volume. They
submit 10x more reports.

8.4 Rejection is data. Every N/A teaches you something about the program's
standards, the program's scope, or your methodology.

8.5 The statistical view: each submission is a roll of the dice. More dice
rolls = more wins. Don't get attached to any single submission.

### Learning from Rejection

8.6 When a report is rejected, ask: "What would have made this report accepted?"
Was it insufficient impact? Wrong bug class? Missing evidence? Scope ambiguity?

8.7 Rejection reason patterns: "Informational only" = needs more impact
demonstration. "Out of scope" = better scope review needed. "Low severity" =
chain it with something bigger.

8.8 N/A with no explanation: the triager didn't have time to explain. Do not
take this personally. It tells you the program is overwhelmed, not that your
finding was bad.

8.9 Each rejection should lead to one methodology improvement. "Next time I
will capture better evidence." "Next time I will check if this is already
known." "Next time I will include a clearer impact statement."

8.10 Keep a rejection log. Track the reasons. After 20 rejections, analyze
the pattern and fix the most common cause.

### Emotional Management

8.11 Do not submit findings when you're emotionally attached to them. The
rejection hurts more, and you're more likely to argue with triagers over
nothing.

8.12 Submit findings dispassionately. The report is a data point, not your
child. The program can reject it without rejecting you.

8.13 If a rejection frustrates you, close the browser tab and walk away.
Do not write a rebuttal while frustrated. Come back the next day.

8.14 Celebrate rejections as learning. "I just learned that this program
doesn't pay for missing cookie flags. That's valuable information I can use
elsewhere."

8.15 The difference between a $10k month and a $0 month is often luck, not
skill. A single critical finding can make a month. Variance is high.

### Speed of Rebound

8.16 After a rejection, submit another finding as quickly as possible. The
fastest cure for rejection anxiety is a new submission.

8.17 Do not "take a break from bug bounty" after a rejection. This reinforces
the idea that rejection is bad. Rejection is normal. Keep going.

8.18 The day after a rejection should be your most productive day. Channel
the frustration into methodology improvement.

8.19 Rejections are proof that you're submitting. Many hunters never submit
because they're afraid of rejection. You're already ahead of them.

8.20 Rejection resilience is a skill that improves with practice. The 100th
rejection hurts less than the 1st. Keep submitting.

---

## 9. INFORMATION ASYMMETRY

The best hunters use every available piece of information to gain an advantage.
Information asymmetry — knowing more than other hunters — is the foundation of
consistent success.

### Using Disclosed Reports for Advantage

9.1 Every disclosed report on a program is a free lesson in what that program
considers a valid finding. Read every single one before testing.

9.2 Disclosed reports reveal the program's vulnerability taxonomy. If they
categorize reports as "Improper Access Control" rather than "IDOR," search
for that category.

9.3 Looking for gaps in disclosed reports: if the program has 100 disclosed
reports and none are GraphQL-related, either the program doesn't use GraphQL
or no one has tested it. Assume the latter until proven otherwise.

9.4 Disclosed reports reveal endpoint naming patterns. If accepted reports
mention `/api/v2/users/{id}/profile`, there's likely an `/api/v1/` version
that's less secure.

9.5 The severity assigned to disclosed reports is the best predictor of what
your report will be assigned. If a similar IDOR was rated "High," yours will
likely be "High" too.

### Reading Between the Lines of Program Updates

9.6 Program updates that mention "security improvements" mean the program
recently fixed bugs. The fixes may have introduced new vulnerabilities.

9.7 "We've updated our scope to include X" means the program wants hunters
testing X. X is likely new and untested.

9.8 "We've updated our bounty amounts" means the program is actively investing
in bug bounty. Now is the time to hunt.

9.9 "We've added clarification to our rules" usually means the program had a
dispute with a hunter. The clarification often reveals what the program is
sensitive about.

9.10 Program updates that are defensive in tone suggest recent negative
experiences. The program may be more conservative in triage. Factor this
into your target selection.

### Monitoring Changelogs for New Features

9.11 Every SaaS application has a changelog. Public changelogs reveal feature
launches, deprecations, and architecture changes. Each change is potential
attack surface.

9.12 API changelogs are the most valuable. New endpoints. New parameters.
Deprecated endpoints that still work but are no longer maintained.

9.13 Browser extension changelogs reveal features before they're publicly
launched. If you can find the extension's API calls, you can test unreleased
features.

9.14 Mobile app changelogs often reveal endpoints not in the web application.
APK decompilation is essential recon.

9.15 Changelog pattern: "Fixed a security issue where..." reveals the exact
type of vulnerability the application has. Go find similar issues.

### Tracking GitHub Commits

9.16 Public GitHub repositories of the target organization are a goldmine.
Commit messages often reference security fixes, new features, and infrastructure
changes.

9.17 Commit messages containing "fix", "security", "auth", "permission",
"validation", "sanitize" are high-value signals. Read the diff if possible.

9.18 Branches with feature-in-development names reveal future attack surface.
The code is in the repository, it may already be deployed behind feature flags.

9.19 The target's `.github` directory may reveal CI/CD configuration,
deployment scripts, and testing infrastructure. All of these have security
implications.

9.20 GitHub Actions workflows: if the target uses self-hosted runners, a
workflow injection vulnerability could give you code execution in the
target's internal network.

### Certificate Transparency for New Subdomains

9.21 Monitor certificate transparency logs for new subdomains of your target.
crt.sh is the standard tool, but automate it via API.

9.22 Every new subdomain is a potential new attack surface. Subdomains for
staging, development, internal tools, and new features appear in CT logs
before they're public.

9.23 Rapid certificate issuance (multiple certs for the same domain in 24
hours) suggests active infrastructure changes. Something is being deployed.

9.24 Wildcard certificates reveal naming patterns. `*.api.company.com` tells
you there are multiple API subdomains to discover.

9.25 Certificate re-issuance (a cert issued, then re-issued with different
SANs) suggests domain changes. Old subdomains may have been removed from
the cert but still resolve.

### Other Information Sources

9.26 Job postings: Companies hiring for security roles are actively investing
in security. They likely have bugs to find but also better detection.

9.27 Job postings for developers reveal tech stacks. "We're looking for a
React/Node developer" is the stack you'll be testing against.

9.28 Support documentation: Internal knowledge bases that are publicly
accessible reveal feature details, configuration options, and edge cases.

9.29 Third-party integrations: If the target integrates with a service that
has known vulnerabilities, test those integration points.

9.30 Regulatory filings (SOC 2, ISO 27001 reports): These reveal the
company's security controls. "Anti-malware, firewalls, access controls" —
generic. But if they mention "quarterly penetration tests," you know
infrastructure is tested periodically.

---

## 10. THE HUNTER'S EDGE

What truly separates top earners ($100k+/year) from the rest ($0-$10k/year)?
It's not tools, not intelligence, not even time spent. It's approach.

### Deeper Testing

10.1 Average hunter: tests if an IDOR exists by changing user IDs in the URL.
Top hunter: tests if IDOR exists in WebSocket messages, in API response fields,
in file names, in error messages, in export functions, in batch operations, in
cached responses.

10.2 Average hunter: finds XSS and moves on. Top hunter: finds XSS, then asks
"Can I chain this with CSRF? Can I bypass CSP? Can I steal the CSRF token?
Can I pivot this to an ATO?"

10.3 Average hunter: tests input validation with obvious payloads. Top hunter:
tests input validation with encoding variations, with unicode normalization,
with parser differentials, with truncation attacks.

10.4 The difference between a medium finding and a critical finding is usually
not the vulnerability itself but the demonstration of impact. "Reflected XSS"
is low. "Reflected XSS on the admin panel that can be used to create an admin
account" is critical.

10.5 Every vulnerability should be tested for: can it be escalated? Can it be
chained? Can it be weaponized? If the answer is no, it's a low or medium.

### Chain Construction

10.6 The ability to chain two low-severity findings into a high-severity
finding is the most valuable skill in bug bounty.

10.7 Common chains:
  - Information disclosure + IDOR = account compromise
  - CORS misconfiguration + XSS = data theft
  - CSRF + XSS = wormable attack
  - Rate limiting bypass + credential stuffing = account takeover
  - Open redirect + OAuth = token theft
  - SSRF + internal service = RCE
  - Subdomain takeover + cookie scope = account takeover

10.8 Chain construction requires understanding the application's data flow.
You can't chain what you don't understand. Invest time in application mapping.

10.9 A chain is only as strong as its weakest link. If any step in the chain
is not reliably exploitable, the chain fails. Prove every step.

10.10 Documentation matters more for chains than for single bugs. The triager
needs to understand each step of the chain. Screenshot every intermediate
state.

### Less-Saturated Bug Classes

10.11 XSS, SQLi, and CSRF are saturated. Every hunter tests for them. The
low-hanging fruit is gone on every major program.

10.12 Business logic bugs are less saturated because they require application-
specific understanding. The barrier to entry is higher, so competition is lower.

10.13 Race conditions are under-tested because they require tooling and
understanding of concurrency. Most hunters don't know how to test for them.

10.14 Prototype pollution in Node.js applications is under-tested because it's
a relatively recent class. Many programs have open prototype pollution bugs.

10.15 JWT attacks are under-tested because hunters assume the JWT library
handles security. Most JWT libraries have insecure defaults, and many
applications customize JWT handling unsafely.

10.16 HTTP request smuggling is under-tested because it requires understanding
of HTTP protocol details and specific tooling.

10.17 XML external entity (XXE) injection is under-tested because JSON has
replaced XML in most modern APIs. But any endpoint accepting XML (even
hidden behind JSON) is vulnerable.

10.18 Server-side template injection (SSTI) is under-tested because hunters
don't recognize template expressions in error messages or responses.

10.19 Cache poisoning/deception is under-tested because hunters don't
understand CDN behavior.

10.20 Mass assignment is under-tested because hunters don't know which
fields the application uses internally.

### Reading Code vs Black-Box

10.21 Black-box hunting is testing without source code. It's the most common
approach. It requires understanding the application's behavior through
observation.

10.22 Code-reading hunting (when source is available) is exponentially more
effective. Every vulnerability you find in code is one no other hunter has
found through black-box testing.

10.23 If a program has a public GitHub, download the code. Search for:
  - TODO and FIXME comments (known bugs)
  - API keys and tokens in code (credential leaks)
  - Routes without authentication middleware
  - SQL queries built with string concatenation
  - File operations without path validation
  - Deserialization without type checking

10.24 Code reading reveals attack surface no black-box testing can reach.
Internal endpoints, admin routes, debug functions, unused methods.

10.25 If you can't read the full source, read the JavaScript bundles served
to the browser. They contain API endpoints, internal routes, and sometimes
API keys.

### Understanding the Business

10.26 Top earners understand what the business values. An e-commerce company
values revenue (payment bugs, discount abuse). A social network values trust
(account takeover, impersonation). A cloud provider values data isolation.

10.27 Business understanding enables business logic hunting. You can't exploit
a flawed subscription downgrade if you don't understand the subscription model.

10.28 The best chain primitives come from understanding the business model.
"How does this company make money? Where does user data flow? What are the
trust boundaries?"

10.29 Business context determines severity. A bug that lets you read another
user's email on a social network is medium. The same bug on a healthcare
application is critical.

10.30 Read the company's privacy policy, terms of service, and security page.
They reveal what data the company considers sensitive. That's what you should
target.

### Methodology Discipline

10.31 Top hunters have written methodologies they follow for every target.
They don't "wing it." They have checklists, processes, and procedures.

10.32 Methodology discipline means you don't miss entire classes of bugs
because you forgot to test for them. Your checklists ensure coverage.

10.33 Written methodology enables consistency. A good methodology produces
results on any target, regardless of the hunter's mood, energy, or motivation
that day.

10.34 Methodology evolves. After each session, review what worked and what
didn't. Update your methodology. Continuous improvement.

10.35 Share your methodology. Teaching others forces you to articulate your
process, which reveals gaps and improvements.

---

## 11. COMPETITION AWARENESS

You are not testing an application in a vacuum. There are other hunters testing
the same endpoints. Understanding the competitive landscape helps you hunt smarter.

### Understanding What Other Hunters Are Testing

11.1 Check disclosure feeds for the program. Recent accepted reports reveal
what bug classes are being found and what endpoints are being tested.

11.2 If three IDOR reports were accepted in the last week, other hunters are
testing IDOR on this target. Move to a different bug class.

11.3 If no GraphQL reports exist for a program that uses GraphQL, GraphQL is
untested. This is your opportunity.

11.4 If reports are concentrated on certain endpoints (e.g., `/api/v2/users`),
other hunters have already tested those endpoints thoroughly. Test different
endpoints.

11.5 The timing of recent reports matters. A burst of reports followed by
silence for 3 weeks suggests the low-hanging fruit is gone and hunters have
moved on. Deeper testing may be productive.

### Avoiding Saturated Targets/Bug Classes

11.6 Programs with large hunter counts (100+ active hunters) are saturated.
Unless you have a unique methodology or access, your findings will likely
be duplicates.

11.7 Private programs with small hunter counts (10-30) have less competition.
The same effort produces more unique findings.

11.8 New public programs have a flood of hunters for the first 2-4 weeks.
During this window, only obvious bugs are found quickly. After the flood
recedes, deeper testing becomes viable.

11.9 Bug classes that are easy to automate (XSS, SQLi, CSRF, open redirect)
are the most saturated. Automated scanners find these. Manual testing should
focus on bugs that scanners miss.

11.10 Bug classes that require application understanding (business logic,
race conditions, authentication logic, authorization bypass) are less
saturated. These require human effort that scales poorly.

### Timing Strategies

11.11 Hunt when other hunters are sleeping. If your target audience is in
Europe, hunting during European daytime means more competition. Hunting during
European night means less competition.

11.12 Weekend hunting: fewer hunters active. More time to find bugs before
others duplicate.

11.13 Holiday hunting: most hunters take holidays off. Major bug discoveries
during holiday weeks are common because competition is lowest.

11.14 Post-launch window: the first 48 hours after a new feature launch is
the most competitive. Everyone is testing it. Wait 72 hours and test when
others have moved on.

11.15 End-of-month hunting: some hunters stop after they've had a good month.
The last week of the month may have less competition.

### Finding Underexplored Surface

11.16 New endpoints that don't appear in documentation: fuzz for undocumented
endpoints. Other hunters won't test what they don't know exists.

11.17 Old endpoints that the UI no longer references: the UI was updated, but
the old endpoint still works. No one is testing it because the UI doesn't
point to it.

11.18 Endpoints that require specific configuration: feature flags, specific
account types, specific user roles. If you can create accounts with different
configurations, you find surface others can't reach.

11.19 Mobile API endpoints: most hunters test web applications. Mobile API
endpoints (used by iOS/Android apps) are often less tested.

11.20 Third-party integrations: endpoints that communicate with third-party
services are tested by fewer hunters because they require understanding of
the integration.

### Reading the Competitive Landscape

11.21 HackerOne trends: which bug classes are trending up? Which are trending
down? Follow the up-trending classes before they become saturated.

11.22 Twitter/Discord chatter: if everyone is talking about a specific
technique or target, it's saturated. Go where the noise isn't.

11.23 Conference talks and blog posts: after a popular talk on a new technique,
everyone tests it for the next month. Don't join the crowd. Test something else.

11.24 Tool availability: when a new tool is released that automates a bug
class, that bug class becomes saturated within weeks. Focus on bug classes
that can't be automated.

11.25 Researcher migrations: when a group of researchers moves from one
platform to another (e.g., from H1 to Immunefi), they bring competition with
them. Platform competition is important.

---

## 12. RISK MANAGEMENT

Bug bounty hunting takes place on production systems. Mistakes have real
consequences. Risk management is not optional.

### Testing Safely

12.1 Never test with destructive payloads: DELETE operations without
verification, DROP TABLE, rm -rf, mass email sends, large data modifications.

12.2 Read-only first: always use GET requests to explore before using POST,
PUT, PATCH, or DELETE.

12.3 If you must modify data, modify your own test data. Create test accounts
with test names, test email addresses, and test data.

12.4 When testing SSRF, use services you control (Burp Collaborator, webhook.site,
your own domain). Do not target internal services you haven't verified.

12.5 When testing RCE, use benign commands that prove code execution without
damage: `sleep 5`, `id`, `whoami`, `cat /etc/passwd` (read-only).

12.6 When testing race conditions, limit concurrency. 50 concurrent requests
is usually enough. 10,000 concurrent requests may trigger DoS protections or
actually degrade service.

12.7 When testing SQL injection in production, use time-based techniques that
return quickly. `SLEEP(5)` is safer than `SLEEP(30)`.

### Avoiding Detection

12.8 Rate limiting exists for a reason. Respect it. 100 requests per second
will trigger alerts. Space your requests human-like.

12.9 Randomize your request timing. A request every exact 5 seconds is
bot-like. Vary between 3-8 seconds.

12.10 Use legitimate user agents, not default tool user agents. The
application logs `curl/7.68.0` and `python-requests/2.25.0`.

12.11 Rotate IP addresses if you're testing at scale. A single IP making
10,000 requests is obvious. Multiple IPs making 1,000 requests each is less
obvious.

12.12 Do not test authentication endpoints aggressively. 10 failed login
attempts on a single account will trigger account lockout and alert the
security team.

12.13 Use test accounts, not real user accounts. If you compromise a real
user's account during testing, you have a real problem.

12.14 Clear cookies, local storage, and session data between testing
sessions. You don't want evidence of previous testing polluting new sessions.

12.15 Use a dedicated testing browser profile separate from your personal
browser. This prevents accidental cross-contamination.

### Staging vs Production Awareness

12.16 Always verify you are testing the correct environment. Staging
applications may have different data, different configurations, and different
security controls.

12.17 Staging environments often have weaker security — debug mode enabled,
default credentials, no rate limiting, verbose errors. Finding bugs in staging
is less valuable because staging is not production.

12.18 If you find a bug in staging, test if the same bug exists in production.
If it does, report the production bug. Staging-only bugs may still be
acceptable but are lower impact.

12.19 Staging environments may have production data. If a staging DB is
connected to a production data source, a staging bug becomes a production
breach.

12.20 Production environment: assume everything is monitored. Every request
is logged. Every error is alerted. Every anomaly is investigated.

### Data Exfiltration Limits

12.21 Do not exfiltrate more data than necessary to demonstrate the
vulnerability. Three user records proves the point. 10,000 user records is
a data breach.

12.22 Capture screenshots of data as evidence. Do not download databases,
export CSVs, or scrape large datasets.

12.23 If you find an endpoint that returns all users' data, demonstrate with
a single record. Do not abuse the endpoint to build a user database.

12.24 PII (personal identifiable information) should never be published
anywhere. Redact emails, names, phone numbers, addresses, and financial data
in your reports.

12.25 Once you have demonstrated data access, stop accessing data. Document
the vulnerability and submit. Continuing to access data after proof is
unnecessary and risky.

### Legal Boundaries

12.26 The program's scope document is a legal agreement. If it says "XSS only
on *.app.example.com," do not test XSS on admin.example.com.

12.27 Out-of-scope vulnerabilities should not be tested or exploited, even if
you find them accidentally. Report them to the program and ask if they want
testing.

12.28 Do not test social engineering attacks (phishing, vishing, smishing)
unless explicitly authorized. These are illegal in most jurisdictions.

12.29 Do not test physical security (office access, badge cloning, tailgating)
unless explicitly authorized. This is trespassing.

12.30 Do not test denial of service. Even a single request that causes a
service outage is a real outage.

12.31 If you find a vulnerability that could cause a service outage, do not
exploit it to prove impact. Describe the vulnerability and the theoretical
impact.

12.32 Do not modify or delete other users' data. Even if an IDOR allows it,
doing so without authorization is illegal data tampering.

### Account Safety

12.33 Use a VPN or proxy when hunting. Your IP address should not be
permanently associated with your hunting activity.

12.34 Use burner email addresses and phone numbers where possible. Do not use
your personal email for test accounts.

12.35 Create test accounts with unique, non-identifying usernames. "TestUser1"
not "YourNameBugHunter."

12.36 Do not use your primary bug bounty platform account on test
environments. The environments may log credentials.

12.37 Password hygiene: use different passwords for testing accounts, your
bug bounty platform, and your email. Password reuse is the #1 account takeover
vector.

12.38 2FA everything: bug bounty platforms, email accounts, GitHub. Your
hunting accounts are high-value targets.

---

## 13. LEARNING INVESTMENT

Bug bounty is a craft that rewards continuous learning. The hunters who invest
in learning consistently outperform those who don't.

### Time Investment in Learning

13.1 Allocate 10-20% of your total hunting time to learning. If you hunt 20
hours a week, spend 2-4 hours learning.

13.2 Learning compounds. Every new technique you learn applies to every future
target. A week spent learning GraphQL basics pays off across 50 programs.

13.3 The learning curve of a new skill is steep but short. Most vulnerability
classes can be learned to a productive level in 4-8 hours of focused study.

13.4 Learning is not passive reading. Read a writeup, then go reproduce the
finding on a test application or a live program. Active learning sticks.

13.5 Keep a learning log. After learning a new technique, note what you
learned, what resources you used, and how you plan to apply it.

### New Tech Stacks

13.6 Each new tech stack you learn opens up a new category of programs.
Learning AWS Lambda opens serverless programs. Learning Solidity opens
Immunefi. Learning React Native opens mobile app bounties.

13.7 When learning a new stack, focus on the security-relevant aspects first:
  - Authentication mechanisms in this stack
  - Common misconfigurations
  - Known vulnerabilities in popular packages
  - Framework-specific security features and their bypasses

13.8 Build a test environment for each stack you learn. A simple CRUD
application with a deliberately vulnerable endpoint lets you practice.

13.9 Stack diversity prevents burnout. If you're tired of testing Rails
applications, learning Go opens a new, refreshing landscape.

13.10 Stack knowledge transfer: many concepts transfer between stacks.
Understanding mass assignment in Rails helps you understand mass assignment
in Laravel. Understanding SSTI in Jinja2 helps you understand SSTI in Twig.

### New Vulnerability Classes

13.11 If you've never found a race condition bug, spend a week learning race
conditions. Read writeups. Build a test harness. Practice on programs.

13.12 The 80/20 rule for vulnerability classes: 80% of your time on classes
you know (productive), 20% on classes you're learning (investment).

13.13 Vulnerability classes go through hype cycles. Prototype pollution was
huge in 2022. SSRF was huge in 2021. Race conditions are trending now.
Learn the next trend before it peaks.

13.14 Deep dive vs broad: spend one month going deep on a single class
(prototype pollution from basics to advanced exploitation). Then spend one
month broad across multiple classes. Alternate.

13.15 Write your own vulnerable application to practice a new class. It forces
you to understand how the vulnerability works, not just how to exploit it.

### Tool Mastery

13.16 Master one tool at a time. Don't try to learn Burp, Caido, ffuf,
nuclei, subfinder, and waybackurls all at once. Learn one to proficiency,
then add another.

13.17 Burp extensions are force multipliers. Learn to write your own Burp
extensions (Python with Jython or Java). Automate repetitive tasks.

13.18 ffuf mastery: understanding filter options (status codes, response size,
word count, regex) triples your fuzzing efficiency.

13.19 JavaScript analysis tools: master LinkFinder, SecretFinder, or their
modern equivalents. Every JS bundle is an endpoint discovery opportunity.

13.20 Terminal proficiency: if you're slow at the command line, you're slow
at hunting. Invest time in shell scripting, piping, and text processing (grep,
sed, awk, jq for JSON).

### The Learning Curve Payoff Curve

13.21 The first hour of learning a new skill has low payoff — you're confused
and slow.

13.22 Hours 2-5 have rapidly increasing payoff — you start to understand the
concepts and find simple examples.

13.23 Hours 5-20 have peak payoff — you can find bugs in the class on real
programs.

13.24 Hours 20-100 have diminishing payoff — you're refining technique, not
learning new concepts.

13.25 The key insight: you don't need 100 hours of study. You need 5-10 hours
to become productive in a new class. The 10-hour investment repays itself
within weeks.

---

## 14. SESSION PLANNING

Every hunting session should have a purpose, a plan, and a review.
Wandering through an application without a plan wastes time and misses bugs.

### Pre-Session Preparation

14.1 Before starting a session, review your target notes. What did you test
last time? What signals remain? What endpoints haven't you touched?

14.2 Set a clear objective for the session: "I will test all endpoints in the
user management module for IDOR" or "I will review the JS bundles from the
last deployment for new endpoints."

14.3 Objectives should be specific and bounded. "Test the application" is not
an objective. "Test password reset flow for token prediction" is an objective.

14.4 Prepare your tools before the session. Burp configured. ffuf wordlist
ready. VPN connected. Accounts logged in. The session should start with
testing, not setup.

14.5 Review relevant resources before the session. If you're testing password
reset, review the last three password reset findings you found on other
programs. Pattern recognition works best when patterns are fresh.

14.6 Set an estimated time for the session and set a timer. When the timer
goes off, stop and review, even if you're in the middle of something.

### Goal Setting for Each Session

14.7 Session goals should be output-oriented, not outcome-oriented. "Test 20
endpoints with the IDOR checklist" is output-oriented. "Find an IDOR" is
outcome-oriented. You can control output, not outcome.

14.8 Output goals prevent frustration. If you tested 20 endpoints, the session
was a success regardless of whether you found anything.

14.9 Outcome-focused sessions lead to disappointment. You can do everything
right and find nothing. That's not failure.

14.10 Set stretch goals but accept base goals: "I will test 20 endpoints
(base) and ideally find one IDOR (stretch)."

14.11 Write down your goal before the session. Writing commits you. A mental
goal is a wish. A written goal is a plan.

### Session Structure

14.12 Phase 1 (0-15 minutes): Review. What did I find last time? What signals
was I tracking? What changed in the application?

14.13 Phase 2 (15-90 minutes): Execute. Work through your checklist. Test
endpoints systematically. Capture everything.

14.14 Phase 3 (90-110 minutes): Document. Write down what you found. Capture
screenshots. Save requests. You will forget details within hours.

14.15 Phase 4 (110-120 minutes): Review. What worked? What didn't? What should
you do next time?

14.16 Do not skip any phase. Skipping review means repeating mistakes.
Skipping documentation means losing findings. Skipping documentation during
hunting means having to recreate requests later.

### Post-Session Review

14.17 Immediately after the session, write a session summary:
  - What I tested
  - What I found (including "nothing interesting")
  - What signals remain
  - What I would do differently

14.18 Review what you learned. Did you discover a new technique? A new
endpoint pattern? A new framework behavior? Note it.

14.19 Update your personal knowledge base. The session taught you something.
Capture it before you forget.

14.20 Rate your session productivity. Was the objective appropriate? Was the
time estimate right? Adjust next session accordingly.

14.21 If you found nothing, review your methodology. Was the objective
reasonable? Did you test systematically? Did you miss obvious vectors?

### Knowledge Capture

14.22 Maintain a target-specific notebook. Each target gets its own page or
document with notes on endpoints tested, findings, and signals.

14.23 Maintain a technique notebook. Each time you learn a new technique or
testing approach, write it down. This becomes your personal methodology
document.

14.24 Maintain a "lessons learned" log. After each finding (success or
failure), note what you learned that you can apply next time.

14.25 Knowledge capture is not optional. The difference between a hunter who
improves and one who stagnates is whether they learn from each session.

### Continuous Improvement Cycle

14.26 Plan: Set objectives based on previous session review.

14.27 Do: Execute the session with discipline.

14.28 Check: Review what happened. What worked? What didn't?

14.29 Act: Update methodology based on review.

14.30 Repeat: The cycle never ends. Continuous improvement is the only path
to mastery.

---

## 15. OSINT MINDSET

Everything the application does is data. Every response tells a story.
Develop the reflex to extract information from every interaction.

### URLs Reveal Architecture

15.1 URL patterns reveal application architecture. `/api/v2/users/123/profile`
tells you: there's an API, at least version 2, there are users, users have
IDs (numeric), users have profiles.

15.2 URL naming conventions reveal developer intent. `getUserData` vs
`get_user_data` vs `GetUserData` — naming conventions reflect the development
team's style and potentially the programming language.

15.3 URL path depth reveals application complexity. Shallow paths
(`/api/endpoint`) suggest a simple or new application. Deep paths
(`/api/v2/users/123/profile/settings/notifications`) suggest a mature
application with nested resources.

15.4 Undocumented URL parameters reveal feature flags. If the UI sends
`?feature=standard`, there may be `?feature=premium` or `?feature=admin`.

15.5 URL changes between environment reveals deployment patterns.
`app.company.com` vs `api.company.com` vs `cdn.company.com` reveal
microservice boundaries.

### Error Messages Reveal Stack

15.6 MySQL error: `You have an error in your SQL syntax` = MySQL database.
SQLite error: `no such column` = SQLite (unlikely in production).
PostgreSQL error: `ERROR: column »x« does not exist` = PostgreSQL.

15.7 Node.js error: stack traces with `at` statements showing file paths.
Python error: `Traceback (most recent call last)` with `.py` files.
Java error: `Exception in thread "main"` with fully qualified class names.
.NET error: Yellow screen of death with .NET version.

15.8 Framework identifiers in error messages: `Symfony`, `Laravel`, `Django`,
`Express`, `Rails`, `Spring`. Each framework has specific error page styles.

15.9 Cloud provider in error messages: `AWS Lambda` headers, `GCP` error pages,
`Azure` error pages. Cloud provider defines the attack surface.

15.10 CDN in error messages: `Cloudflare` error pages, `Akamai` headers,
`Fastly` headers. CDN indicates which caching and WAF protections exist.

### Timing Reveals Infrastructure

15.11 Response time differences between static and dynamic content reveal
deployment characteristics. Fast static = CDN. Fast dynamic = in-memory
caching or edge computing.

15.12 Consistent response times across different request types suggest a
single-threaded event loop (Node.js, Python async). Variable response times
suggest multi-threaded or multi-process (Java, Go, .NET).

15.13 Initial request slow, subsequent requests fast = lazy initialization
or cold start. Common in serverless (AWS Lambda, Cloud Functions). Cold
start vulnerabilities exist in the init phase.

15.14 Periodic latency spikes suggest cron jobs, backup processes, or
garbage collection. Test during these windows for race conditions.

15.15 Geo-location based timing differences reveal data centers. Fast in
us-east, slow in Europe = us-east based origin. Test from different locations
to map infrastructure.

### Headers Reveal Configuration

15.16 `Server` header: `Apache/2.4.41` = version, `nginx/1.18.0` = version,
`gunicorn/20.0.4` = Python WSGI server.

15.17 `X-Powered-By`: `PHP/7.4.1`, `Express`, `ASP.NET` — reveals server-side
technology.

15.18 `Set-Cookie` attributes: `HttpOnly`, `Secure`, `SameSite` reveal
security maturity. Missing attributes = older or less security-aware
development.

15.19 `Access-Control-Allow-Origin`: dynamic value = CORS misconfiguration.
Static value = intentional CORS policy.

15.20 `X-Frame-Options`: missing = clickjacking possible. `DENY` = framed
somewhere. `SAMEORIGIN` = same-origin framing.

15.21 `Content-Security-Policy`: restrictive = security-aware. Missing or
permissive (`default-src *`) = XSS exploitation possible.

15.22 `Strict-Transport-Security`: missing = no HSTS. Low `max-age` = recent
enforcement. High `max-age` = mature security posture.

15.23 `Via` header = proxy/cache in use. `X-Cache` = cache hit/miss.
`X-Proxy` = WAF or reverse proxy.

15.24 `X-Request-Id` or `X-Trace-Id` = logging infrastructure. The header
format reveals the tracing system (e.g., AWS X-Ray, custom).

15.25 `X-RateLimit-*` headers = rate limiting implementation. Learn the limits,
find the bypass.

### Response Body OSINT

15.26 HTML comments in the response: `<!-- TODO: implement auth -->`,
`<!-- @TODO: remove debug=true -->`, `<!-- Feature X deprecated, use Y -->`.

15.27 Hidden form fields: `<input type="hidden" name="role" value="user">`
can be changed to `admin`. `<input type="hidden" name="price" value="99.99">`
can be changed to `0`.

15.28 JavaScript variables embedded in HTML: `var API_KEY = "abc123";` or
`var apiEndpoint = "https://internal-api.company.com"` or
`var isAdmin = false;`.

15.29 JSON-LD or structured data: `@context`, `@type` reveal data models
and sometimes internal schemas.

15.30 Data attributes on HTML elements: `data-user-id="123"`,
`data-role="admin"`, `data-csrf-token="token123"`. All manipulable.

### JavaScript OSINT

15.31 Endpoints in JavaScript: AJAX calls, fetch calls, axios configs all
contain endpoint URLs. Every URL in JS is a potential attack surface.

15.32 API keys in JavaScript: Google Maps API keys, Stripe publishable keys,
Mixpanel tokens. Some are safe (public keys), some are not (secret keys in
client-side code).

15.33 Internal IP addresses in JavaScript: comments, config files, error
handling code may contain private IP ranges.

15.34 Feature flags in JavaScript: `if (features.enableNewAuth)` reveals
unreleased features that may already be accessible.

15.35 Error handling code in JavaScript: `catch (err) { console.log(err) }`
was supposed to be removed. The error log function is usually more verbose
in development.

### DNS and Infrastructure OSINT

15.36 DNS records reveal infrastructure. CNAME records point to cloud
services (`company.com -> company.cloudfront.net`, `company.com -> company.s3.amazonaws.com`).

15.37 MX records reveal email provider. Google Workspace, Office 365, custom
mail servers. Email provider is a potential attack vector.

15.38 TXT records reveal SPF, DKIM, DMARC configuration. Missing SPF =
email spoofing possible.

15.39 Subdomain enumeration reveals attack surface. Every subdomain is a
potential entry point. `admin.company.com`, `dev.company.com`,
`staging.company.com`, `api.company.com`, `cdn.company.com`.

15.40 CNAME to unregistered service = subdomain takeover. If
`blog.company.com` CNAMEs to `company.github.io` and the GitHub page is
deleted, you can claim it.

### Authentication OSINT

15.41 Login page reveals auth provider. Custom login = custom auth (more
likely to have flaws). SSO login (Google, GitHub, Okta) = third-party auth
(different flaws).

15.42 Password policies reveal security maturity. "Password must be 6
characters" = weak. "Password must be 12+ characters with special chars" =
strong. "No password policy on the page" = tested by API, not frontend.

15.43 Registration page reveals account structure. Email required? Phone
required? Username format? These tell you about the data model.

15.44 Password reset flow reveals auth implementation. Email-based reset with
token in URL = standard. SMS-based reset = test SS7. Security questions =
test for guessable answers.

15.45 MFA options reveal security posture. TOTP = standard. SMS = weak.
Push notification = medium. Security key (FIDO2/WebAuthn) = strong. No MFA =
the application may not be sensitive enough to warrant MFA, or the developer
didn't implement it.

---

## 16. THEORY OF CONSTRAINTS

Every hunter has a bottleneck that limits their productivity. Identify yours
and fix it. The Theory of Constraints applied to bug bounty.

### Identifying Your Constraint

16.1 Your constraint is the single factor that, if improved, would most
increase your finding rate.

16.2 Common constraints:
  - Recon depth (not enough endpoints discovered)
  - Tool availability (don't have the right tools for the bug class)
  - Account access (can't test authenticated features)
  - Bug class knowledge (don't know how to test certain classes)
  - Target selection (choosing programs with low payout or high competition)
  - Writing efficiency (spending too much time on reports)
  - Time management (not enough focused hunting time)
  - Persistence (giving up too early on hard targets)
  - Chain construction (finding primitives but not exploiting them)

16.3 To find your constraint, ask: "What is the limiting factor in my last
10 sessions?" If you spent 20 hours fuzzing and found no bugs, your constraint
is recon depth or target selection. If you found bugs but didn't submit them,
your constraint is writing efficiency.

16.4 Track your sessions. After each session, note what limited your
productivity. After 10 sessions, analyze the pattern.

16.5 Ask a mentor or peer to review your methodology. Sometimes your
constraint is invisible to you but obvious to others.

### Common Constraints and Their Fixes

16.6 Constraint: Recon depth
  - Fix: Learn subdomain enumeration. Use subfinder, crt.sh, amass.
  - Fix: Learn URL crawling. Use katana, waybackurls, gau.
  - Fix: Learn directory fuzzing. Use ffuf with good wordlists.
  - Fix: Learn JS bundle analysis. Download and search for endpoints.

16.7 Constraint: Tool availability
  - Fix: Learn Burp Suite deeply, not just proxy mode.
  - Fix: Install and configure ffuf, nuclei, httpx.
  - Fix: Set up Burp extensions (Autorize, Logger++, JS Miner).
  - Fix: Build a testing proxy chain (Burp -> Caido -> Custom).

16.8 Constraint: Account access
  - Fix: Create test accounts manually on your targets.
  - Fix: Look for programs that provide test accounts.
  - Fix: Use free tiers of the application.
  - Fix: Share accounts with trusted researcher friends (where allowed).
  - Fix: Check if the application has a trial mode without credit card.

16.9 Constraint: Bug class knowledge
  - Fix: One week of deep study per class.
  - Fix: Reproduce disclosed writeups on test applications.
  - Fix: Join communities focused on specific classes.
  - Fix: Read the OWASP testing guide for the class.

16.10 Constraint: Target selection
  - Fix: Spend more time researching programs before committing.
  - Fix: Create a target ranking system based on potential payout/hour.
  - Fix: Focus on new programs and recent scope additions.
  - Fix: Drop targets that aren't producing results.

16.11 Constraint: Writing efficiency
  - Fix: Create report templates for common bug classes.
  - Fix: Document as you go, not after hunting.
  - Fix: Use snipping tools with auto-save for screenshots.
  - Fix: Write the impact statement first, then fill in details.

16.12 Constraint: Time management
  - Fix: Use the 20-minute rotation rule strictly.
  - Fix: Follow 90-minute focus blocks without interruption.
  - Fix: Use Pomodoro technique (25 min work, 5 min break).
  - Fix: Block calendar time for hunting.

16.13 Constraint: Persistence
  - Fix: Lower your threshold for switching targets.
  - Fix: Accept that most targets will produce zero findings.
  - Fix: Focus on the process, not the outcome.
  - Fix: Volume of targets tested correlates with findings.

16.14 Constraint: Chain construction
  - Fix: After finding a primitive, spend 30 minutes brainstorming chains.
  - Fix: Keep a chain idea list — primitives you've found that could chain.
  - Fix: Read chain-based disclosed reports for patterns.

### Fixing Your Constraint Systematically

16.15 Dedicate one week to constraint elimination. If your constraint is
recon depth, spend a full week building your recon pipeline, no hunting.

16.16 The investment in constraint elimination pays for itself. A week spent
improving your recon pipeline improves every future session.

16.17 Fix one constraint at a time. Trying to fix everything at once fixes
nothing.

16.18 After fixing a constraint, reassess. What is your new constraint? The
constraint shifts. Fix the next one.

16.19 Your constraint will change over time. When you were a beginner, bug
class knowledge was the constraint. As an intermediate, target selection
may be the constraint. As an advanced hunter, chain construction may be
the constraint.

16.20 The best hunters are aware of their current constraint and actively
working on it. Constraint awareness is a meta-skill.

---

## 17. MENTAL MODELS

Mental models are frameworks for thinking about applications and
vulnerabilities. They help you see bugs that others miss.

### The Developer Shortcuts Model

17.1 Every shortcut a developer takes creates a potential vulnerability. The
shortcut is a decision to not implement something correctly, completely, or
securely.

17.2 Common shortcuts:
  - "I'll just trust the client" = no server-side validation = mass assignment,
    price manipulation, IDOR
  - "I'll use the session ID as the user ID" = session-based auth without
    authorization checks = any authenticated user can access any resource
  - "I'll return the whole object" = no field filtering = data leakage in
    API responses
  - "I'll make it work first, add auth later" = no auth = unprotected access
  - "I'll copy this from Stack Overflow" = unknown security implications =
    deserialization, injection, XXE
  - "I'll use the default configuration" = insecure defaults = debug endpoints
    exposed, verbose errors, weak ciphers
  - "I'll skip input validation for internal endpoints" = trust-based
    security = vulnerabilities reachable via SSRF or CSRF

17.3 Finding shortcuts: look for code that was written quickly or in a
hurry. Error-prone patterns include: TODO comments, copy-pasted code blocks,
inconsistent naming conventions, and code that differs significantly from
surrounding code.

17.4 Shortcut patterns repeat. If you find one shortcut that led to a bug,
look for similar shortcuts elsewhere in the same application.

17.5 The shortcut model predicts: when you find the first vulnerability in an
application, there are more. Shortcuts don't exist in isolation.

### The Unexpected Input Model

17.6 Applications break when they receive input the developer didn't anticipate.
The goal of hunting is to find inputs that the developer never considered.

17.7 Types of unexpected input:
  - Wrong type: string for an integer, object for an array
  - Wrong format: JSON for XML, XML for JSON
  - Extreme values: very large, very small, negative, zero
  - Empty values: null, undefined, empty string, empty array
  - Special characters: quotes, angle brackets, semicolons, null bytes
  - Unicode: emoji, homoglyphs, right-to-left override, combining chars
  - Repetition: same key multiple times, deeply nested structures
  - Encoding: double URL encoding, different character encodings
  - Timing: concurrent requests, out-of-order requests, long delays

17.8 For each parameter, ask: "What would happen if I sent X instead of what
the UI sends?" for each type of unexpected input.

17.9 The unexpected input model predicts: the most robust-looking applications
have the most surprising failures because developers spent the least time
testing edge cases.

17.10 The unexpected input model also applies to user behavior, not just
API input. Unexpected user behavior (running two sessions, sharing accounts,
using ad blockers, disabling JavaScript) can trigger bugs.

### The Boundary Model

17.11 Bugs cluster at boundaries. Boundaries between:
  - Authenticated and unauthenticated access
  - Admin and regular user permissions
  - Different API versions (v1 vs v2)
  - Different environments (staging vs production)
  - Different data types (string vs number)
  - Different states (active vs inactive, paid vs trial, public vs private)
  - Different input sources (web vs mobile vs API)

17.12 At every boundary, check:
  - Is the transition handled correctly?
  - Can I cross the boundary in an unexpected order?
  - Can I cross the boundary without the expected prerequisite?
  - Can I prevent the boundary from being crossed?

17.13 Common boundary bugs:
  - V1 endpoint has weaker auth than V2, but V1 is still accessible
  - Admin panel checks admin role on the frontend but not on the backend
  - Trial accounts can access premium features by directly calling the API
  - Public posts become private but the old public URL still works
  - Data is validated on creation but not on update (boundary between create
    and update)

17.14 The boundary model predicts: the most bugs exist at the edges of
features, not in the core functionality. Test what happens when you move
between states.

### The Shift Model

17.15 Change one thing and see what breaks. The "shift" is any variation
from the expected flow.

17.16 Shifts to test:
  - Method shift: GET to POST, POST to PUT, DELETE to GET
  - Auth shift: authenticate, then de-authenticate mid-flow
  - State shift: create a resource, then delete it, then access it
  - Permission shift: gain admin role, lose admin role, what persists?
  - Session shift: open two sessions, perform operations in session A,
    check session B
  - Time shift: create a resource, wait, check if it still behaves correctly
  - Order shift: perform operations in reverse or different order than expected
  - Count shift: perform an operation once, then twice, then 100 times

17.17 The shift model predicts: applications are tested in the expected flow.
The bugs are in the unexpected flow. Shift something and watch what breaks.

17.18 The more complex the flow, the more shift points exist. A simple CRUD
endpoint has 4 shift points (create, read, update, delete). A multi-step
checkout has 20+.

### The Trust Model

17.19 Applications trust certain things implicitly. Finding what the
application trusts and proving that trust is misplaced is the essence of
hunting.

17.20 Things applications trust:
  - Client-provided IDs (IDOR)
  - Client-provided prices (price manipulation)
  - Client-provided roles (privilege escalation)
  - Internal IP addresses (SSRF)
  - HTTP headers (header injection, host header attacks)
  - Cookies (CSRF, session fixation)
  - JWTs (JWT attacks when trust is misplaced)
  - Third-party data (injection via compromised third parties)
  - Cached data (cache poisoning/deception)
  - User-provided files (file upload vulnerabilities)

17.21 The trust model predicts: find what the application trusts without
verification, and you've found a vulnerability class.

17.22 The trust model is recursive: the application trusts the auth service,
the auth service trusts the identity provider, the identity provider trusts
the user's credentials. Trust chains can be exploited at any link.

### The Legacy Model

17.23 Old code has old vulnerabilities. If a component was written 5+ years
ago, it was written against a different threat model.

17.24 Legacy indicators:
  - `/api/v1/` paths alongside `/api/v2/` or `/api/v3/`
  - Old endpoint patterns (`/getUser.php?id=1`) alongside modern patterns
    (`/api/users/1`)
  - PHP, ASP, or older Java frameworks
  - Different authentication mechanisms for different parts of the app
  - Different error message formats suggesting different development eras

17.25 The legacy model predicts: legacy code is the most vulnerable code in
the application. Find the old stuff and test it aggressively.

### The Feature Flag Model

17.26 Feature flags control which features are visible and which are hidden.
Hidden features often have security gaps because they were not intended to
be accessible.

17.27 Feature flag detection:
  - Boolean values in JavaScript: `enable_new_auth: false`
  - URL parameters: `?feature=new-ui`
  - Headers: `X-Feature-Flags: beta`
  - Cookie values: `feature_flags=premium,beta,admin`
  - User attributes: `role: "beta_tester"`
  - API responses with undocumented fields that look like toggles

17.28 The feature flag model predicts: for every application, there are
hidden features accessible by toggling undocumented switches.

### The Cache Model

17.29 Cached responses behave differently from uncached responses. This
difference is exploitable.

17.30 Cache behavior differences:
  - Cached responses don't check auth (if cache key doesn't include auth)
  - Cached responses serve stale data after permissions change
  - Cached responses can be poisoned by manipulating cache keys
  - Cached responses can expose data meant for other users (cache deception)
  - Different cache rules apply to different content types

17.31 The cache model predicts: any application behind a CDN has a different
security posture than the origin server. Attack the CDN behavior, not just
the origin.

### The State Machine Model

17.32 Applications are state machines with valid and invalid state transitions.
Bugs exist in invalid transitions.

17.33 State machine analysis:
  - Map all states: unauthenticated, authenticating, authenticated, MFA,
    onboarding, active, suspended, deleted
  - Map all valid transitions: login, logout, register, verify, suspend,
    reactivate, delete
  - Test invalid transitions: delete without suspension, login without
    verification, MFA skip, reactivation without re-verification

17.34 The state machine model predicts: the more states an application has,
the more invalid transitions exist. Complex auth flows have the most bugs.

### The Default Model

17.35 Default configurations are optimized for ease of use, not security.
Developers rarely change defaults.

17.36 Defaults to check:
  - Passwords: `admin/admin`, `admin/password`, `root/root`
  - Paths: `/admin`, `/wp-admin`, `/api`, `/docs`
  - Ports: 8080, 3000, 5000, 8000, 8443
  - Configurations: debug mode on, verbose errors on, directory listing on,
    auto-indexing on

17.37 The default model predicts: if a technology has an insecure default,
every application using that technology has that vulnerability unless they
explicitly changed it.

### The Race Condition Model

17.38 Time is a resource. When operations are not atomic, there is a window
where concurrent access can corrupt state.

17.39 Race condition patterns:
  - Check-then-act: verify balance, then withdraw = withdraw twice before
    balance is updated
  - First-write-wins: two simultaneous writes to the same resource = last
    write overwrites first
  - Delete-then-create: delete old data, create new = access the gap where
    neither exists
  - Read-then-write: read a token, then verify = use token after verification
    but before expiry window

17.40 The race condition model predicts: any operation that reads, transforms,
and writes data in separate steps has a potential race condition.

---

## 18. EVIDENCE-FIRST MINDSET

Evidence is the currency of bug bounty. Without evidence, you have nothing.
Develop the discipline of capturing everything as you go.

### Capture as You Go

18.1 The moment you see something interesting, capture it. Do not wait until
"after you finish testing" — you will forget the exact request, the exact
response, and the exact context.

18.2 Default to capturing more rather than less. You can delete evidence
later. You cannot recreate a finding without evidence.

18.3 Set up your environment for automatic evidence capture:
  - Burp: enable logging of all requests and responses to a file
  - Screenshot tool: one-key screenshot (Windows: Win+Shift+S, Mac: Cmd+Shift+4)
  - Clipboard history: enable clipboard manager to save copied text

18.4 For every interesting finding, capture:
  - The full request (from Burp or similar)
  - The full response (including headers)
  - The timestamp
  - The endpoint URL
  - Your authentication state (logged in as which user?)
  - Any relevant application state (resource IDs, session tokens)

18.5 Screenshots should capture:
  - The browser URL bar (proves location)
  - The network tab (proves request/response)
  - The application state (proves you're logged in as a specific user)
  - Any console output (proves client-side behavior)

### Organization Discipline

18.6 Organize evidence by target and date. `TargetName/2026-06-06/` is a
good structure. Within each date folder, label screenshots descriptively:
`idor-user-123-profile-data.png`

18.7 Maintain a running document for each hunting session. Paste findings,
observations, and thoughts as you go. The document becomes the foundation
of your report.

18.8 Use a consistent labeling scheme for evidence. `{target}-{bugclass}-
{endpoint}-{descriptor}.{ext}`. Example:
`acme-idor-users-123-admin-data.png`

18.9 Back up your evidence. Local drive failure should not mean lost findings.
Cloud storage, external drive, or both.

18.10 Evidence organization is not "admin work" — it is part of the hunting
process. Treat it as such.

### Why Evidence Cannot Be Recreated

18.11 The exact conditions under which you found a bug may never occur again.
Rate limiting may kick in. The resource may be deleted. Your account may
be banned. The application may change.

18.12 Reproducing a finding takes time. If you captured the evidence during
the finding, your report is complete. If you need to reproduce, you're adding
30-60 minutes of work.

18.13 Third-party dependencies change. The integration that was vulnerable
today may be patched tomorrow. Capture evidence now.

18.14 Session state is ephemeral. The CSRF token that worked for this request
expired. The session that had this permission was revoked. The admin account
you used was deleted.

18.15 The more steps in your chain, the harder it is to reproduce. Capture
each step of the chain as evidence. A screenshot of the final state only
proves the final state, not how you got there.

### What to Screenshot

18.16 The login page for each account you use (proves you have the account).

18.17 The account profile showing your username/email (proves identity).

18.18 The request in Burp Repeater with the modified parameter (proves
what you changed).

18.19 The response showing the leaked data (proves impact).

18.20 The response with the modified header (proves the injection).

18.21 The developer console showing the error (proves client-side behavior).

18.22 The network tab showing the request chain (proves sequence of requests).

18.23 The application state after exploitation (proves session/data access).

18.24 The same endpoint without the exploit (proves normal behavior for
comparison).

18.25 The cookie values in the browser (proves authentication context).

### The Evidence Mindset

18.26 Evidence is not optional. A finding without evidence is a claim, not
a proof.

18.27 The triager will not reproduce your finding. They will read your report
and look at your evidence. Make the evidence tell the story.

18.28 Evidence tells the story of the exploit. A good set of evidence is a
visual walkthrough of the attack, from start to finish.

18.29 Evidence protects you. If a program questions your finding, your evidence
is your defense.

18.30 The habit of evidence capture is the habit of professionalism. It
separates serious hunters from casual testers.

---

## 19. HUNTING IN THE DARK

Not every program provides authenticated access. Many of the best findings
come from public-facing surface that doesn't require login.

### Public-Facing Surface Analysis

19.1 The public-facing application (no login required) is the first thing
anyone tests. But most hunters test the login page and move on. The public
surface is deeper than most realize.

19.2 Public endpoints to test:
  - Landing pages and marketing sites (XSS, open redirect, host header)
  - Search functionality (SQLi, XSS, NoSQLi)
  - Contact forms (email injection, SSRF via webhook)
  - API documentation pages (API keys in docs, endpoint discovery)
  - Blog or news sections (SSTI, path traversal)
  - User-generated content pages (XSS, HTML injection)
  - Cookie consent banners (DOM XSS, third-party script injection)
  - Password reset pages (user enumeration, token prediction)
  - Registration pages (mass assignment, rate limiting bypass)
  - Login pages (credential stuffing, SQLi, NoSQLi)
  - Error pages (stack traces, information disclosure)
  - Sitemap.xml and robots.txt (hidden paths)
  - /.well-known/ (security.txt, openid-configuration)

19.3 Public endpoints often share infrastructure with authenticated endpoints.
An SSRF in a contact form can reach internal APIs that require authentication.

### JS Bundle Mining

19.4 JavaScript bundles are the single richest source of endpoint information
in modern web applications. Every framework bundles routes, API calls, and
configuration into JavaScript.

19.5 Download all JS files from the application:
  - Look at the network tab during page load
  - Use tools like LinkFinder, JSParser, or custom scripts
  - Check for lazy-loaded JS files (loaded on specific user actions)

19.6 Search JS bundles for:
  - API endpoint URLs (`/api/`, `/graphql`, `/v1/`, `/v2/`)
  - Internal domain names (`internal.company.com`, `api-internal.company.com`)
  - API keys and tokens (`apiKey:`, `secret:`, `token:`)
  - Endpoint paths that don't appear in the UI
  - Admin routes (`/admin`, `/dashboard`, `/manage`)
  - Feature flags and hidden features
  - Debug functions (`console.log`, `debugger`, `test()`)

19.7 JS bundle versioning reveals application evolution. Compare current
bundles with historical versions (via Wayback Machine) to see what changed.

19.8 Minified JS is harder to read but not impossible. Use JS beautifiers.
Search for URL patterns with regex: `https?://[^"'\s]+`, `/[\w/-]+/[\w-]+`,
`api|graphql|rest|[0-9]+\.\.[a-z]+`.

19.9 Source maps (`.map` files) are sometimes deployed to production. If you
can access `app.js.map`, you get the original source code with comments,
variable names, and structure.

### Wayback Machine History

19.10 The Wayback Machine (archive.org) stores historical versions of web
pages. Every historical version is a snapshot of the attack surface at a
different point in time.

19.11 Historical endpoints that no longer appear in the UI may still be
functional. The application removed the link but kept the endpoint.

19.12 Historical API responses may have contained data (API keys, tokens)
that were present in an older version and still valid.

19.13 Historical JS bundles contain endpoints that were removed or changed.
The old endpoints may still work with the current application.

19.14 Compare historical and current versions of the same page. Differences
reveal what the application changed — and potentially what they forgot to
change.

19.15 Tools for Wayback: gau (get all URLs), waybackurls, and manual browsing
at web.archive.org.

### Misconfigured Endpoints

19.16 Some of the most valuable public endpoints are misconfigurations:
  - Open S3 buckets (public read/write)
  - Open Firebase databases (no auth rules)
  - Open Elasticsearch instances (public API)
  - Open Grafana/Dashboards (no auth)
  - Open Jenkins instances (no auth, script console available)
  - Open Git repositories (.git/config exposed)
  - Open environment files (.env exposed)
  - Open configuration files (config.json, config.php, settings.py exposed)
  - Open database backups (.sql, .dump, .backup files exposed)
  - Open admin panels with default credentials

19.17 Tools for finding misconfigurations:
  - nuclei (templates for thousands of misconfigurations)
  - bucket-stream (monitors S3 buckets)
  - Shodan (search for exposed services)
  - Censys (certificate and service search)
  - Project Discovery Chaos (subdomain enumeration with bucket check)

19.18 Misconfiguration discovery requires persistence. Most are found by
scanning thousands of subdomains and services until one responds without auth.

19.19 A single misconfiguration can be the highest payout of your career.
Open S3 buckets with customer data, open Firebase with user credentials,
open Jenkins with production access.

### Default Credentials

19.20 Default credentials are the oldest vulnerability in the book and still
one of the most common.

19.21 Default credential databases:
  - `admin/admin`, `admin/password`, `admin/123456`
  - `root/root`, `root/toor`, `root/123456`
  - `test/test`, `test/123456`, `test/password`
  - `user/user`, `user/password`, `user/123456`
  - Vendor defaults: `cisco/cisco`, `netgear/netgear`, `ubnt/ubnt`

19.22 Default credentials work on:
  - Admin panels
  - API documentation tools (Swagger, Postman)
  - Monitoring dashboards (Grafana, Kibana)
  - Database management tools (phpMyAdmin, Adminer)
  - Development tools (Jenkins, GitLab, Jira)

19.23 Finding default credential opportunities:
  - Search for admin panels via directory fuzzing
  - Search for development tools via subdomain enumeration
  - Search for monitoring dashboards via port scanning

19.24 Default credentials are low-hanging but real. Many programs accept them,
especially if they lead to sensitive data access.

### The Unauthenticated Chain

19.25 A single public-facing vulnerability can be the entry point to the
entire application:

19.26 XSS in a public page -> steal cookies from users who visit -> access
authenticated features -> escalate to admin.

19.27 SSRF in a public contact form -> reach internal metadata service
(AWS 169.254.169.254) -> access cloud credentials -> pivot to internal
resources.

19.28 Open S3 bucket -> find application config files with database
credentials -> connect directly to the database.

19.29 SQL injection in public search -> extract admin credentials -> login
as admin -> full access.

19.30 Host header injection on public page -> generate password reset links
that redirect to attacker -> take over any account -> access authenticated
features.

19.31 The unauthenticated chain mindset: every public vulnerability is a
foothold. The foothold is not the finding. The chain is the finding.

---

## 20. GROWTH MINDSET

Bug bounty is a craft that rewards continuous improvement. The hunters who
keep growing are the hunters who keep finding.

### Learning from Every Finding

20.1 Every finding teaches you something. Even a duplicate finding is a data
point: "This bug exists, others found it first, I need to test faster or
test different things."

20.2 After each accepted finding, ask: "What made this finding work? What
was the root cause? How can I find more of this type?"

20.3 After each rejected finding, ask: "Why was this rejected? Was it the
impact? The evidence? The bug class? The target choice?"

20.4 Write a post-mortem for every finding. One page. What I did, what I
found, what I learned, what I would do differently.

20.5 The post-mortem habit compounds. After 100 findings, you have 100 pages
of accumulated wisdom. This is your personal methodology manual.

### Building Hunt Memory

20.6 Hunt memory is the ability to recognize patterns across targets:
"Endpoint X on target A behaves the same as endpoint Y on target B where I
found an IDOR."

20.7 Building hunt memory requires intentional pattern recognition. After each
target, note the framework, the endpoint patterns, the auth model, and the
vulnerability types you found.

20.8 Pattern recognition notebook: keep a running list of associations.
"Target A (Rails) had mass assignment on user update. Target B (Node) had
mass assignment on profile update. Both used `update_attributes` equivalent."

20.9 The more targets you test, the more patterns you recognize. This is why
experienced hunters find bugs faster — they've seen the same pattern on 50
previous targets.

20.10 Hunt memory is domain-specific. A hunter with 100 Rails targets tested
can predict Rails bugs within minutes. A hunter with 100 React targets tested
can predict frontend bugs within minutes.

### Mentoring and Community

20.11 Teaching others is one of the best ways to learn. Explaining a
technique forces you to articulate what you know, revealing gaps in your
understanding.

20.12 Join communities where hunters share techniques. Discord servers, Slack
groups, forums. The collective knowledge of the community is a force multiplier.

20.13 Contribute to the community. Write writeups. Share techniques. Answer
questions. The more you give, the more you receive.

20.14 Be open about failures. The hunter who shares "I spent 30 hours on a
target and found nothing" is more valuable than the hunter who only shares
successes. Failures teach more than successes.

20.15 Find a mentor or be a mentor. The mentor relationship accelerates
learning for both parties. Mentors see your blind spots. Mentees remind you
of fundamentals.

### Continuous Improvement Cycle

20.16 The Plan-Do-Check-Act cycle applied to bug bounty:
  - Plan: Set learning goals for the month
  - Do: Execute sessions focused on those goals
  - Check: Review what worked and what didn't
  - Act: Update methodology based on review

20.17 Monthly reflection: at the end of each month, review your findings,
your rejections, and your learning goals. Adjust for the next month.

20.18 Quarterly audit: every 3 months, audit your entire methodology. What
bug classes have you not tested recently? What new techniques have emerged?
What tools have you not mastered?

20.19 The growth mindset is not about being better than other hunters. It's
about being better than you were last month.

20.20 The learning never stops. The application landscape evolves. New
frameworks emerge. New vulnerability classes are discovered. New techniques
are developed. The hunter who stops learning stops finding.

### The Long Game

20.21 Bug bounty is a marathon, not a sprint. The hunters who last are the
ones who pace themselves. Burnout is the #1 reason hunters quit.

20.22 Sustainable hunting means:
  - Hunting hours that don't interfere with life
  - Taking days off without guilt
  - Celebrating successes without overconfidence
  - Learning from failures without despair
  - Building skills that compound over years, not weeks

20.23 The best hunters are not the ones who find the most bugs in a month.
They are the ones who are still hunting 5 years later. Consistency beats
intensity.

20.24 Your portfolio of skills, knowledge, and relationships compounds.
Every target you test, every technique you learn, every person you connect
with adds to your compound growth.

20.25 The hunter's journey is infinite. There is no "mastery" — only
continuous improvement. Every session is a step forward, even when it doesn't
feel like it. Keep hunting.

---

## FINAL WORDS

These 1200+ rules codify the psychological framework, strategic thinking, and
operational discipline of effective bug bounty hunting. They are not rules to
be memorized — they are habits to be internalized.

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
