---
name: Js-analysis
description: JavaScript/TypeScript source code security analysis specialist. Covers JS security patterns, API endpoint extraction from bundles, secret/key extraction, prototype pollution detection, DOM XSS sink identification, client-side auth analysis, WebSocket security, postMessage vulnerabilities, and source map exploitation. Includes grep patterns, extraction tools, and analysis methodology for modern JS frameworks (React, Vue, Angular, Next.js). Use when: analyzing JavaScript files, extracting endpoints from bundles, hunting for secrets in JS, testing client-side security, or auditing SPAs. Chinese trigger: JS分析、JavaScript审计、前端安全、源码分析、API提取、前端漏洞
---

# Skill: JS Analysis

Analyze JavaScript like a pro. Find endpoints, secrets, and vulns in JS bundles.

## Core Concept

Modern web apps are 80% JavaScript. The server sends a thin HTML shell + a massive JS bundle. That bundle contains:
- All API endpoints
- All secret keys and tokens
- Business logic
- Authentication flows
- Hidden features

**If you skip JS analysis, you skip 50% of the attack surface.**

---

## JS File Discovery

### Find All JS Files

```bash
# From URL list
cat urls.txt | grep "\.js$" | sort -u > jsfiles.txt

# From live hosts
cat live.txt | awk '{print $1}' | while read url; do
    curl -s "$url" | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'
done | sort -u > jsfiles.txt

# From HTML parsing (more reliable)
katana -d 3 -silent -jc -o urls.txt
cat urls.txt | grep "\.js$" | sort -u > jsfiles.txt

# Include source maps
cat jsfiles.txt | grep -v "\.map$" > jsfiles-main.txt
cat jsfiles.txt | grep "\.map$" > jsfiles-maps.txt
```

### Prioritize JS Files

```
Priority 1: app.js, main.js, bundle.js, index.js (main bundles)
Priority 2: chunk-*.js, vendor.js (third-party code)
Priority 3: *.chunk.js (code-split chunks)
Priority 4: Source maps (*.js.map) — deobfuscate these first
Priority 5: Third-party libs (less interesting unless outdated)
```

---

## API Endpoint Extraction

### Method 1: String Pattern Matching

```bash
# Extract API URL patterns
cat app.js | grep -oE 'https?://[^"'\''>\s]+api[^"'\''>\s]*' | sort -u
cat app.js | grep -oE '"/api/[^"'\''>\s]+"' | sed 's/"//g' | sort -u
cat app.js | grep -oE "'/api/[^\"' >\s]+'" | sed "s/'//g" | sort -u

# Extract fetch/axios calls
cat app.js | grep -oE 'fetch\s*\(\s*["'\''`][^"'\''`]+["'\''`]\s*[^)]*\)'
cat app.js | grep -oE 'axios\.[a-z]+\s*\(\s*["'\''`][^"'\''`]+["'\''`]'
cat app.js | grep -oE '\.get\s*\(\s*["'\''`][^"'\''`]+["'\''`]'
cat app.js | grep -oE '\.post\s*\(\s*["'\''`][^"'\''`]+["'\''`]'
cat app.js | grep -oE '\.put\s*\(\s*["'\''`][^"'\''`]+["'\''`]'
cat app.js | grep -oE '\.delete\s*\(\s*["'\''`][^"'\''`]+["'\''`]'
```

### Method 2: Regex for Endpoint Patterns

```bash
# Comprehensive endpoint extraction
cat app.js | grep -oE '/(api|v1|v2|graphql|rest|users|admin|auth|login|register|search|query|export|import|upload|download|settings|profile|account|orders|payments|transactions|invoices|reports|data|files|documents|messages|notifications|webhooks|hooks|callback|webhook)[^"'\''>\s]{0,100}' | sort -u > endpoints.txt

# GraphQL endpoints
cat app.js | grep -i "graphql\|/gql\|/query" | sort -u

# WebSocket endpoints
cat app.js | grep -oE 'wss?://[^"'\''>\s]+' | sort -u

# REST patterns with parameters
cat app.js | grep -oE '/(users|orders|products|invoices|transactions|payments)/[0-9]+' | sort -u
```

### Method 3: jsluice (Best Tool)

```bash
# Install
go install github.com/eth0izzle/sl0t/jsluice/cmd/jsluice@latest

# Extract endpoints
jsluice endpoints -i app.js

# Extract secrets
jsluice secrets -i app.js

# Extract domains
jsluice domains -i app.js

# Extract potential interesting strings
jsluice potential -i app.js
```

### Method 4: LinkFinder (Python)

```bash
# Install
pip3 install linkfinder

# Run
python3 linkfinder.py -i app.js -o endpoints.txt

# Or via CLI
python3 -c "
import re, sys
content = open(sys.argv[1]).read()
endpoints = re.findall(r'https?://[^\s\"'<>]+', content) + \
            re.findall(r'/api/[^\s\"'<>]+', content) + \
            re.findall(r'/v[0-9]+/[^\s\"'<>]+', content)
print('\n'.join(sorted(set(endpoints))))
" app.js
```

### Method 5: Manual Framework Detection

```bash
# Detect framework
grep -l "react\|vue\|angular\|svelte\|next\|nuxt" package.json

# React: look for .js files with JSX
# Vue: look for .vue files or vue-loader patterns
# Angular: look for @angular/* in imports
# Next.js: look for _app.js, _document.js, pages/ in paths
```

---

## Secret Extraction

### Secret Patterns to Search

```bash
# AWS keys
grep -oE 'AKIA[0-9A-Z]{16}' app.js
grep -oE '(AWS|aws)_(ACCESS|SECRET|KEY)_?ID?\s*[:=]\s*["\047][A-Za-z0-9/+=]{20,}["\047]' app.js

# Generic API keys
grep -oE '(api[_-]?key|apikey|api_secret|api_token|client_secret)\s*[:=]\s*["\047][A-Za-z0-9_\-]{20,}["\047]' app.js -i

# JWT tokens
grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' app.js

# Bearer tokens
grep -oE 'Bearer\s+[A-Za-z0-9_\-\.]+' app.js

# Private keys
grep -oE '-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----' app.js

# Firebase
grep -oE 'https://[A-Za-z0-9-]+\.firebaseio\.com' app.js
grep -oE 'firebaseConfig\s*[:=]\s*\{[^}]+\}' app.js

# Stripe
grep -oE 'sk_live_[0-9a-zA-Z]{24,}' app.js
grep -oE 'pk_live_[0-9a-zA-Z]{24,}' app.js

# GitHub tokens
grep -oE 'gh[ops]_[A-Za-z0-9_]{36,}' app.js

# Slack
grep -oE 'xox[baprs]-[0-9a-zA-Z-]+' app.js

# Google
grep -oE 'AIza[0-9A-Za-z\-_]{35}' app.js  # Google API key

# Generic secrets
grep -oE '(secret|password|token|key)\s*[:=]\s*["\047][A-Za-z0-9_\-\.]{10,}["\047]' app.js -i

# URLs with credentials
grep -oE 'https?://[^:]+:[^@]+@[^/\s]+' app.js
```

### Tool: SecretFinder

```bash
# Install
pip3 install secretfinder

# Run
python3 SecretFinder.py -i https://target.com/app.js -o cli
python3 SecretFinder.py -i app.js -o cli

# Custom patterns
python3 SecretFinder.py -i app.js -o cli \
  -g api_keys,emails,ips,secretes
```

### Tool: JSScanner

```bash
# Install
pip3 install jsscanner

# Run
jsscanner -f app.js
```

---

## Prototype Pollution Detection

### What Is It?

Prototype pollution lets attackers modify `Object.prototype` properties, affecting all objects in the application.

```javascript
// VULNERABLE: merges user input without filtering
let obj = {};
obj = merge(obj, JSON.parse(userInput));
// If userInput contains: {"__proto__": {"isAdmin": true}}
// Then ALL objects in the app have isAdmin = true

// CONFIRMATION
console.log({}.isAdmin);  // true if polluted
console.log(Object.keys({}));  // ["isAdmin"] if polluted
```

### Detection Patterns

```bash
# Look for merge/assign with user input
grep -rn "Object\.assign\|\.\.\.\|merge(" --include="*.js" | grep -v node_modules

# Look for deep merge libraries
grep -rn "lodash\|deepmerge\|merge-deep\|extend" --include="*.js" | grep -v node_modules

# Look for JSON.parse with user input
grep -rn "JSON\.parse" --include="*.js" | grep -v node_modules

# Look for __proto__ usage
grep -rn "__proto__\|constructor\[" --include="*.js" | grep -v node_modules
```

### Pollution Payloads

```javascript
// Basic pollution
{"__proto__": {"polluted": true}}
{"__proto__": {"isAdmin": true}}
{"__proto__": {"role": "admin"}}

// Constructor pollution
{"constructor": {"prototype": {"isAdmin": true}}}

// Deep pollution
{"__proto__": {"__proto__": {"isAdmin": true}}}

// XSS via pollution
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}
{"__proto__": {"onerror": "alert(1)"}}
```

### Testing Prototype Pollution

```javascript
// Step 1: Check if pollution works
fetch('/api/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({__proto__: {polluted: true}})
});

// Step 2: Check if polluted
console.log({}.polluted);  // true = vulnerable

// Step 3: Find security sinks
// Check if auth checks rely on polluted properties:
// user.role === 'admin' → if polluted, role = 'admin'
// user.isAdmin === true → if polluted, bypass
```

---

## DOM XSS Sink Analysis

### High-Risk Sinks

```javascript
// HIGHEST RISK
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
document.writeln(userInput);
element.insertAdjacentHTML('beforeend', userInput);

// HIGH RISK
document.documentElement.innerHTML = userInput;
document.body.innerHTML = userInput;

// MEDIUM-HIGH RISK
eval(userInput);
setTimeout(userInput, delay);
setInterval(userInput, delay);
new Function(userInput)();

// MEDIUM RISK (context-dependent)
element.src = userInput;      // javascript: URI
element.href = userInput;     // javascript: URI
location.href = userInput;    // javascript: URI
location.search = userInput;  // reflected in URL
```

### Finding XSS Sinks in JS

```bash
# Find innerHTML assignments
grep -rn "innerHTML\s*=" --include="*.js" | grep -v node_modules

# Find outerHTML assignments
grep -rn "outerHTML\s*=" --include="*.js" | grep -v node_modules

# Find document.write
grep -rn "document\.write" --include="*.js" | grep -v node_modules

# Find eval
grep -rn "eval(" --include="*.js" | grep -v node_modules

# Find dynamic script injection
grep -rn "\.src\s*=" --include="*.js" | grep -v node_modules
grep -rn "\.href\s*=" --include="*.js" | grep -v node_modules
```

### Source-to-Sink Tracing

```
For each XSS sink:
1. Trace the variable back to its source
2. Is the source user-controllable?
   - URL parameter: location.search, URLSearchParams
   - URL hash: location.hash
   - PostMessage: event.data
   - LocalStorage: localStorage.getItem()
   - Cookie: document.cookie
   - User input: form fields, contenteditable
3. Is there sanitization between source and sink?
4. Can the sanitization be bypassed?
```

### Common Sanitization Bypasses

```javascript
// Bypass innerHTML sanitization
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src=javascript:alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

// Bypass URL filters for javascript: URI
javascript:alert(1)
JaVaScRiPt:alert(1)
data:text/html,<script>alert(1)</script>
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;

// Template literal injection (if sink uses .innerHTML with template strings)
${alert(1)}
${constructor.constructor('alert(1)')()}
```

---

## postMessage Vulnerability Analysis

### What Is postMessage?

`window.postMessage()` lets different origins communicate. Dangerous if listener doesn't validate origin.

```javascript
// VULNERABLE: accepts messages from any origin
window.addEventListener('message', function(e) {
    // VULN: no e.origin check
    document.getElementById('output').innerHTML = e.data;
});

// Attack:
// 1. Attacker hosts evil.html
// 2. Victim visits target.com (which has vulnerable listener)
// 3. Attacker opens target.com in iframe
// 4. Attacker sends: iframe.contentWindow.postMessage('<img src=x onerror=alert(1)>', '*')
// 5. XSS fires in target.com context
```

### Detection

```bash
# Find postMessage listeners
grep -rn "addEventListener.*message" --include="*.js" | grep -v node_modules

# Find postMessage calls (senders)
grep -rn "postMessage" --include="*.js" | grep -v node_modules

# Check for origin validation
grep -rn "e\.origin\|event\.origin\|message\.origin" --include="*.js" | grep -v node_modules
```

### postMessage Payloads

```javascript
// XSS via postMessage
window.postMessage('<img src=x onerror=alert(document.domain)>', '*');

// DOM clobbering via postMessage
window.postMessage({__proto__: {isAdmin: true}}, '*');

// Open redirect via postMessage
window.postMessage({redirect: 'https://evil.com'}, '*');

// Exfiltrate data via postMessage
window.postMessage({steal: document.cookie}, '*');
```

### postMessage Testing Checklist

- [ ] Listeners check `e.origin`?
- [ ] If yes: is origin validated against allowlist?
- [ ] Is `e.data` used in XSS sink (innerHTML, eval, etc.)?
- [ ] Can attacker control the message content?
- [ ] Is `targetOrigin` set to `*` in postMessage calls?

---

## Client-Side Auth Analysis

### JWT in JavaScript

```bash
# Find JWT handling
grep -rn "jwt\|token\|decode\|verify\|sign" --include="*.js" | grep -v node_modules

# Check if JWT is stored in localStorage
grep -rn "localStorage\|sessionStorage" --include="*.js" | grep -i "token\|jwt\|auth"

# Check if JWT claims are trusted client-side
grep -rn "role\|admin\|permissions\|scope" --include="*.js" | grep -i "token\|jwt\|decode"
```

### Client-Side Auth Bypasses

```javascript
// 1. Client-side role check (bypassable)
if (user.role === 'admin') {
    showAdminPanel();
}
// Attack: modify localStorage token to {"role": "admin"}

// 2. Feature flag in JS
const ENABLE_ADMIN = false;  // VULN: can be changed in DevTools
if (ENABLE_ADMIN) { ... }

// 3. Hidden endpoint in JS
const API_ENDPOINTS = {
    admin: '/api/admin',  // VULN: exposed in JS
    users: '/api/users'
};

// 4. Client-side redirect based on role
if (user.isAdmin) {
    window.location.href = '/admin';
}
// Attack: intercept response, modify isAdmin flag
```

### Authorization in JS

```bash
# Find role/permission checks
grep -rn "role\|isAdmin\|permissions\|canAccess\|hasPermission" --include="*.js" | grep -v node_modules

# Find admin-only UI elements
grep -rn "admin\|dashboard\|manage\|settings" --include="*.js" | grep -i "show\|display\|render\|visible"

# Find API calls with role parameters
grep -rn "role.*=.*admin\|role.*:.*admin" --include="*.js" | grep -v node_modules
```

---

## WebSocket Security Analysis

### Finding WebSocket Endpoints

```bash
# In JS files
grep -oE 'wss?://[^"'\''>\s]+' app.js | sort -u

# In network tab (manual)
# Look for ws:// or wss:// connections in browser DevTools

# Common patterns
grep -rn "WebSocket\|ws://\|wss://\|new WebSocket" --include="*.js" | grep -v node_modules
```

### WebSocket Vulnerabilities

**1. No Authentication on WebSocket:**
```javascript
// VULN: WebSocket connection without auth check
const ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(event) {
    // Receives messages without authentication
};
```

**2. Sensitive Data in WebSocket Messages:**
```javascript
// VULN: sensitive data sent over WS without auth
ws.send(JSON.stringify({
    type: 'user_data',
    data: { ssn: '123-45-6789', card: '4242...' }
}));
```

**3. Input Validation Missing:**
```javascript
// VULN: no validation on incoming WS messages
ws.onmessage = function(event) {
    const data = JSON.parse(event.data);
    eval(data.code);  // VULN: RCE via WS
};
```

**4. Origin Not Checked:**
```javascript
// VULN: accepts WS from any origin
wss.on('connection', (ws, req) => {
    // Should check Origin header
    ws.on('message', (msg) => { ... });
});
```

---

## Source Map Analysis

### What Are Source Maps?

`.js.map` files contain the original source code before minification. They can reveal:
- Original variable/function names
- Original source code
- Secrets that were minified but not removed

### Finding Source Maps

```bash
# Look for sourceMappingURL comment at end of JS files
grep -l "sourceMappingURL" *.js

# Common source map locations
curl https://target.com/app.js
# Look for: //# sourceMappingURL=app.js.map

# Download source maps
curl https://target.com/app.js.map -o app.js.map

# Check if source maps are accessible
for js in $(cat jsfiles.txt); do
    map="${js}.map"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$map")
    if [ "$code" != "404" ]; then
        echo "[+] Source map found: $map (HTTP $code)"
    fi
done
```

### Analyzing Source Maps

```bash
# Source maps are JSON files with sources content
cat app.js.map | jq '.sources'       # List original source files
cat app.js.map | jq '.sourcesContent' # Original source code!

# Extract all original source files
cat app.js.map | jq -r '.sources[]' | while read source; do
    echo "=== $source ==="
done

# Find secrets in source map
cat app.js.map | jq -r '.sourcesContent[]' | grep -i "api[_-]?key\|secret\|password\|token"

# Find API endpoints in source map
cat app.js.map | jq -r '.sourcesContent[]' | grep -oE '/api/[^"'\''>\s]+'
```

### Source Map Reconnaissance

```bash
# Extract complete original source code
python3 -c "
import json, sys
map_data = json.load(open(sys.argv[1]))
for i, source in enumerate(map_data.get('sources', [])):
    content = map_data.get('sourcesContent', [])[i] if i < len(map_data.get('sourcesContent', [])) else 'N/A'
    print(f'=== {source} ===')
    print(content[:2000])  # first 2000 chars
    print()
" app.js.map
```

---

## Framework-Specific Analysis

### React

```bash
# Find React components
grep -rn "function\s*\w*\s*\(\)\s*{" --include="*.js" | grep -i "component\|render"
grep -rn "class\s*\w*\s+extends\s+React" --include="*.js"

# Find API calls (fetch/axios)
grep -rn "fetch(\|axios\.\|\.get\|\.post\|\.put\|\.delete" --include="*.js" | grep -v node_modules

# Find useEffect (data fetching)
grep -rn "useEffect" --include="*.js" | grep -v node_modules

# Find state management
grep -rn "useState\|useReducer\|useContext\|Redux\|createStore" --include="*.js" | grep -v node_modules

# Find routes (React Router)
grep -rn "Route\|Switch\|Routes\|useHistory\|useNavigate\|path=" --include="*.js" | grep -v node_modules
```

### Vue

```bash
# Find Vue components
grep -rn "new Vue\|createApp\|defineComponent\|Vue\.component" --include="*.js"

# Find API calls
grep -rn "\$http\|axios\|fetch" --include="*.js" | grep -v node_modules

# Find Vue Router
grep -rn "VueRouter\|createRouter\|routes:" --include="*.js"

# Find Vuex/Pinia
grep -rn "Vuex\|createStore\|useStore\|defineStore" --include="*.js"
```

### Angular

```bash
# Find Angular modules
grep -rn "@NgModule\|@Component\|@Injectable" --include="*.js"

# Find HTTP calls
grep -rn "HttpClient\|http\.get\|http\.post" --include="*.js"

# Find routes
grep -rn "RouterModule\|routes:" --include="*.js"
```

### Next.js

```bash
# Find API routes (_app.js, pages/api/)
grep -rn "export\s+default\|export\s+async\s+function\|req\." --include="*.js"

# Find getServerSideProps / getStaticProps
grep -rn "getServerSideProps\|getStaticProps\|getInitialProps" --include="*.js"

# Find middleware
grep -rn "middleware\s*=" --include="*.js" | grep -v node_modules
```

---

## JS Analysis Checklist

### Endpoint Discovery
- [ ] Extracted all API URLs from JS files
- [ ] Checked source maps for hidden endpoints
- [ ] Found GraphQL endpoints
- [ ] Found WebSocket endpoints
- [ ] Extracted versioned API paths (/v1/, /v2/, /api/v2/)

### Secret Discovery
- [ ] Ran SecretFinder on all JS files
- [ ] Checked source maps for secrets
- [ ] Looked for AWS keys, GitHub tokens, Firebase configs
- [ ] Found JWT tokens in JS
- [ ] Checked for API keys in config objects

### XSS Analysis
- [ ] Found all innerHTML/outerHTML assignments
- [ ] Found all document.write calls
- [ ] Found all eval() calls
- [ ] Traced source-to-sink for each XSS sink
- [ ] Checked for sanitization bypasses

### Auth Analysis
- [ ] Found JWT handling code
- [ ] Checked for client-side role checks
- [ ] Found localStorage/sessionStorage token storage
- [ ] Checked for prototype pollution vectors
- [ ] Verified no client-side-only auth

### postMessage Analysis
- [ ] Found all postMessage listeners
- [ ] Checked origin validation
- [ ] Checked if message data reaches XSS sinks
- [ ] Checked WebSocket auth

---

## JS Analysis Tools Summary

| Tool | Purpose | Command |
|------|---------|---------|
| jsluice | Endpoint + secret extraction | `jsluice endpoints -i app.js` |
| SecretFinder | Secret scanning | `python3 SecretFinder.py -i app.js -o cli` |
| LinkFinder | Endpoint extraction | `python3 linkfinder.py -i app.js -o out.txt` |
| Burp JS Miner | Burp extension for JS analysis | Install in Burp |
| Retire.js | Vulnerable library detection | `retire app.js` |
| SourceMapRegexTool | Source map extraction | Custom script |
| GF Patterns | URL/param extraction | `cat app.js \| gf url \| sort -u` |

---

## Retire.js: Vulnerable Library Detection

```bash
# Install
npm3 install retire

# Scan
retire app.js
retire --js --jspull --outputformat json --outputpath results.json

# Or with Node
npx retire --js --jspull
```

### Common Vulnerable Libraries

| Library | Vulnerability | Check |
|---------|--------------|-------|
| jQuery < 3.5.0 | XSS via HTML manipulation | Check jQuery version in JS |
| Angular < 1.8.0 | Multiple XSS/RCE | Check angular.js version |
| React < 16.9.0 | XSS in certain patterns | Check react version |
| Lodash < 4.17.15 | Prototype pollution | Check lodash version |
| Handlebars < 4.4.5 | RCE via lookups | Check handlebars version |

---

## Common JS Vulnerability Patterns

### Pattern 1: Client-Side Auth Bypass

```javascript
// VULN: role check only in JS
const user = JSON.parse(localStorage.getItem('user'));
if (user.role === 'admin') {
    showAdminPanel();
}
// Attacker modifies localStorage → admin access
```

### Pattern 2: Prototype Pollution

```javascript
// VULN: deep merge without filtering
const obj = Object.assign({}, base, JSON.parse(userInput));
// userInput: {"__proto__": {"isAdmin": true}}
```

### Pattern 3: postMessage XSS

```javascript
// VULN: no origin check + innerHTML
window.addEventListener('message', (e) => {
    document.getElementById('output').innerHTML = e.data;
});
```

### Pattern 4: Dynamic Code Execution

```javascript
// VULN: eval with user input
const code = new URLSearchParams(location.search).get('code');
eval(code);  // RCE

// VULN: Function constructor
const fn = new Function('x', 'return ' + userInput);
fn();

// VULN: setTimeout with string
setTimeout(userInput, 1000);
```

### Pattern 5: Insecure WebSocket

```javascript
// VULN: no auth on WS connection
const ws = new WebSocket('wss://target.com/ws');
ws.onmessage = (e) => {
    document.body.innerHTML = e.data;  // XSS
};
```

---

## JS Analysis Report Template

```
## JavaScript Analysis: [Target]

### JS Files Found
- app.js (main bundle, 1.2MB)
- vendor.js (third-party, 800KB)
- chunk-*.js (code-split chunks)

### API Endpoints Extracted
| Method | Endpoint | Notes |
|--------|----------|-------|
| GET | /api/v2/users | List users |
| GET | /api/v2/users/{id} | User detail |
| POST | /api/v2/users/{id}/email | Update email (IDOR?) |
| POST | /api/admin/users | Admin only? |

### Secrets Found
| Type | Value (redacted) | Location |
|------|------------------|----------|
| AWS Key | AKIA... | app.js line 1234 |
| Stripe | sk_live_... | config.js line 56 |

### Vulnerabilities Found
| Vuln Class | Location | Severity |
|-----------|----------|----------|
| Client-side auth bypass | app.js:1234 | High |
| Prototype pollution | merge function | High |
| postMessage XSS | ws-handler.js:45 | High |

### Next Steps
1. Test IDOR on /api/v2/users/{id}/email
2. Verify AWS key access
3. Test postMessage XSS chain
```

---

## Advanced JS Analysis: Framework-Specific Deep Dive

### React Deep Dive

```bash
# Find React components
grep -rn "function\s*\w*\s*\(\)\s*{" --include="*.js" | grep -i "component\|render"
grep -rn "class\s*\w*\s+extends\s+React" --include="*.js"

# Find API calls (fetch/axios)
grep -rn "fetch(\|axios\.\|\.get\|\.post\|\.put\|\.delete" --include="*.js" | grep -v node_modules

# Find useEffect (data fetching on mount)
grep -rn "useEffect" --include="*.js" | grep -v node_modules

# Find state management
grep -rn "useState\|useReducer\|useContext\|Redux\|createStore\|useStore" --include="*.js" | grep -v node_modules

# Find React Router routes
grep -rn "Route\|Switch\|Routes\|useHistory\|useNavigate\|path=" --include="*.js" | grep -v node_modules

# Find dangerouslySetInnerHTML (React XSS)
grep -rn "dangerouslySetInnerHTML" --include="*.js" | grep -v node_modules
```

### Vue Deep Dive

```bash
# Find Vue components and API calls
grep -rn "new Vue\|createApp\|defineComponent\|Vue\.component" --include="*.js"
grep -rn "\$http\|axios\|fetch\|api\." --include="*.js" | grep -v node_modules

# Find Vue Router
grep -rn "VueRouter\|createRouter\|routes:" --include="*.js"

# Find Vuex/Pinia stores
grep -rn "Vuex\|createStore\|useStore\|defineStore" --include="*.js"
```

### Angular Deep Dive

```bash
# Find Angular patterns
grep -rn "@NgModule\|@Component\|@Injectable\|HttpClient" --include="*.js"

# Find API calls
grep -rn "http\.get\|http\.post\|http\.put\|http\.delete" --include="*.js"
```

### Next.js Deep Dive

```bash
# Find API routes and server-side code
grep -rn "export\s+default\|export\s+async\s+function\|getServerSideProps\|getStaticProps\|getInitialProps" --include="*.js"

# Find middleware
grep -rn "middleware\s*=" --include="*.js" | grep -v node_modules

# Find environment variables (NEXT_PUBLIC_ is exposed client-side!)
grep -rn "NEXT_PUBLIC_" --include="*.js" | grep -v node_modules
```

---

## Advanced Secret Discovery

### Comprehensive Secret Pattern Database

```bash
# AWS credentials
grep -oE 'AKIA[0-9A-Z]{16}' *.js
grep -oE '(AWS|aws)_(ACCESS|SECRET|KEY)_?ID?\s*[:=]\s*["\047][A-Za-z0-9/+=]{20,}["\047]' *.js

# Generic API keys (extended patterns)
grep -oE '(api[_-]?key|apikey|api_secret|api_token|client_secret|app_secret)\s*[:=]\s*["\047][A-Za-z0-9_\-\.]{10,}["\047]' *.js -i

# JWT tokens in source
grep -oE '[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}' *.js

# GitHub tokens (multiple formats)
grep -oE 'gh[ops]_[A-Za-z0-9_]{36,}' *.js
grep -oE 'github_pat_[0-9a-zA-Z_]{22,}' *.js

# Google services
grep -oE 'AIza[0-9A-Za-z\-_]{35}' *.js  # API key
grep -oE 'ya29\.[0-9A-Za-z\-_]+' *.js   # OAuth token

# Firebase
grep -oE 'https://[A-Za-z0-9-]+\.firebaseio\.com' *.js
grep -oE 'firebaseConfig\s*[:=]\s*\{[^}]+\}' *.js

# Stripe
grep -oE 'sk_live_[0-9a-zA-Z]{24,}' *.js
grep -oE 'pk_live_[0-9a-zA-Z]{24,}' *.js
grep -oE 'rk_live_[0-9a-zA-Z]{24,}' *.js

# SendGrid
grep -oE 'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}' *.js

# Twilio
grep -oE 'SK[0-9a-fA-F]{32}' *.js

# Mailgun
grep -oE 'key-[0-9a-zA-Z]{32}' *.js

# Slack
grep -oE 'xox[baprs]-[0-9a-zA-Z-]+' *.js

# Heroku
grep -oE 'heroku[a-z0-9-]{20,}' *.js -i

# Algolia
grep -oE '[A-Z0-9]{16}[A-Z0-9]{10}[A-Z0-9]{43}[A-Z0-9]{19}' *.js

# Mapbox
grep -oE 'pk\.[a-z0-9]{60,}' *.js

# Contentful
grep -oE 'CFPAT-[0-9a-zA-Z]{43}' *.js

# Algolia search keys
grep -oE '[a-z0-9]{32}-[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{12}' *.js

# Private keys in JS
grep -oE '-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----' *.js

# URLs with embedded credentials
grep -oE 'https?://[^:]+:[^@]+@[^/\s]+' *.js

# Database connection strings
grep -oE '(mongodb|postgres|mysql|redis|amqp)://[^\s"\047>]+' *.js

# JWT secrets (in code, not in tokens)
grep -oE 'secret\s*[:=]\s*["\047][A-Za-z0-9_\-]{10,}["\047]' *.js -i
```

### SecretFinder Custom Patterns

```bash
# Run SecretFinder with custom regex
python3 SecretFinder.py -i app.js -o cli \
  -g api_keys,emails,ips,secretes,tokens

# Or use with custom patterns file
python3 SecretFinder.py -i app.js -o cli \
  -r custom_patterns.txt
```

---

## Prototype Pollution Deep Dive

### Finding Pollution Vectors

```bash
# Common vulnerable libraries
grep -rn "lodash\|deepmerge\|merge-deep\|extend\|Object\.assign" \
  --include="*.js" | grep -v node_modules

# JSON.parse with user input
grep -rn "JSON\.parse" --include="*.js" | grep -v node_modules

# URL parameter → JSON.parse → merge
grep -rn "URLSearchParams\|location\.search\|new URLSearchParams" \
  --include="*.js" | grep -v node_modules

# POST body → JSON.parse → merge
grep -rn "request\.body\|req\.body\|JSON\.parse" \
  --include="*.js" | grep -v node_modules
```

### Prototype Pollution Exploitation

```javascript
// Step 1: Confirm pollution is possible
fetch('/api/update-profile', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        name: 'attacker',
        __proto__: {isAdmin: true}
    })
});

// Step 2: Check if polluted
console.log({}.isAdmin);  // true = vulnerable

// Step 3: Exploit for auth bypass
// If app checks: if (user.role === 'admin')
// And user object is created from JSON.parse of request body
// Then __proto__ pollution sets role = 'admin' for ALL objects

// Step 4: More advanced pollution
fetch('/api/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        __proto__: {
            isAdmin: true,
            role: 'admin',
            permissions: ['read', 'write', 'delete', 'admin'],
            // XSS via polluted innerHTML
            innerHTML: '<img src=x onerror=alert(document.cookie)>'
        }
    })
});
```

### Finding Sinks for Pollution

```javascript
// After pollution, look for sinks that use polluted properties:

// 1. Auth checks
if (user.role === 'admin')  // polluted role = bypass
if (user.isAdmin)           // polluted isAdmin = bypass
if (user.permissions.includes('admin'))  // polluted permissions = bypass

// 2. HTML rendering
element.innerHTML = user.profile  // polluted innerHTML = XSS

// 3. Template rendering
template(user.data)  // if template uses polluted properties

// 4. Conditional logic
if (config.debug) {...}  // polluted debug = bypass
if (settings.maintenance) {...}  // polluted maintenance = change behavior
```

---

## Advanced XSS Analysis

### Sink Analysis Framework

```
For each XSS sink found:

1. What sources feed into it?
   - URL parameter (location.search, URLSearchParams)
   - URL hash (location.hash)
   - PostMessage (event.data)
   - localStorage/sessionStorage
   - Cookies (document.cookie)
   - Form inputs
   - Server response (fetch/axios response)

2. Is there sanitization?
   - If no sanitization → XSS
   - If sanitization exists → test bypass

3. What's the context?
   - HTML context: element.innerHTML = input
   - Attribute context: element.setAttribute('data-x', input)
   - JavaScript context: eval(input), setTimeout(input)
   - URL context: location.href = input
   - CSS context: element.style = input

4. What can the attacker do?
   - Steal cookies (document.cookie)
   - Make requests as user (fetch)
   - Read page content (DOM access)
   - Modify page content (DOM manipulation)
   - Keylogger (addEventListener('keypress'))
```

### Mutation XSS (mXSS)

```javascript
// VULNERABLE: innerHTML with sanitized input that gets re-parsed
const input = '<img src=x onerror=alert(1)>';
const sanitized = sanitize(input);  // Returns: <img src=x>
element.innerHTML = sanitized;  // Browser parses again → img tag created → XSS

// The sanitizer removes onerror, but when browser parses the resulting HTML:
// <img src=x> → browser auto-adds closing > → img tag created
// XSS fires!

// FIX: Use textContent instead of innerHTML for user data
element.textContent = userInput;
```

### XSS via Template Literals

```javascript
// VULNERABLE: template literal with user input in sink
const userInput = '${alert(1)}';
element.innerHTML = `<div>${userInput}</div>`;
// Result: <div>${alert(1)}</div> → XSS

// Bypass when sanitizer doesn't understand template literals
const payload = '${constructor.constructor("alert(1)")()}';
```

---

## WebSocket Security Deep Dive

### Finding WebSocket Vulnerabilities

```bash
# In JS files
grep -oE 'wss?://[^"'\''>\s]+' *.js | sort -u

# WebSocket message handlers
grep -rn "onmessage\|addEventListener.*message" --include="*.js" | grep -v node_modules

# WebSocket authentication
grep -rn "WebSocket\|new WebSocket\|ws://\|wss://" --include="*.js" | grep -v node_modules
```

### WebSocket Exploitation Patterns

```
1. No authentication on WS connection
   - Attacker connects without valid session
   - Receives sensitive data
   - Can send malicious messages

2. Unsanitized message data
   - Message data rendered in DOM
   - XSS via WebSocket messages

3. Message injection
   - No validation on message format
   - Inject arbitrary messages to other users

4. Origin not checked (server-side)
   - Any origin can connect
   - CSRF-like attacks via WebSocket
```

---

## Source Map Exploitation

### Full Source Map Extraction

```bash
#!/bin/bash
# extract-sourcemaps.sh
TARGET=$1
OUTDIR="sourcemaps/$TARGET"

echo "[*] Extracting source maps for $TARGET"

mkdir -p "$OUTDIR"

# Find JS files with source maps
cat urls.txt | grep "\.js$" | while read js_url; do
    echo "[*] Checking: $js_url"
    
    # Check if JS file mentions source map
    map_url=$(curl -s "$js_url" | grep "sourceMappingURL" | sed 's/.*sourceMappingURL=//;s/[[:space:]]*//')
    
    if [ -n "$map_url" ]; then
        # Resolve relative URL
        if [[ "$map_url" == /* ]]; then
            full_map_url="https://$TARGET$map_url"
        else
            base_url=$(dirname "$js_url")
            full_map_url="$base_url/$map_url"
        fi
        
        echo "  [→] Source map: $full_map_url"
        
        # Download source map
        filename=$(echo "$js_url" | md5sum | cut -d' ' -f1)
        curl -s "$full_map_url" -o "$OUTDIR/$filename.map"
        
        # Extract sources
        echo "  [→] Extracting sources..."
        cat "$OUTDIR/$filename.map" | jq -r '.sources[]' 2>/dev/null | while read source; do
            echo "    Source: $source"
        done
        
        # Extract all source content
        cat "$OUTDIR/$filename.map" | jq -r '.sourcesContent[]' 2>/dev/null > "$OUTDIR/$filename-sources.js"
        
        # Search for secrets in source content
        grep -i "api_key\|secret\|password\|token" "$OUTDIR/$filename-sources.js" | head -10
    fi
done
```

### Source Map Content Analysis

```python
#!/usr/bin/env python3
"""
Analyze source maps for security findings
"""
import json
import re
import sys

def analyze_sourcemap(map_file):
    with open(map_file) as f:
        data = json.load(f)
    
    findings = {
        'secrets': [],
        'endpoints': [],
        'comments': [],
        'debug_code': []
    }
    
    sources = data.get('sourcesContent', [])
    
    for i, source in enumerate(sources):
        source_name = data.get('sources', [])[i]
        
        # Secret patterns
        for pattern in [
            r'[A-Za-z0-9]{40,}',  # Long random strings
            r'AKIA[0-9A-Z]{16}',  # AWS keys
            r'sk_live_[0-9a-zA-Z]{24,}',  # Stripe live keys
            r'gh[ops]_[A-Za-z0-9_]{36,}',  # GitHub tokens
        ]:
            matches = re.findall(pattern, source)
            if matches:
                findings['secrets'].extend([(source_name, m) for m in matches])
        
        # API endpoints
        endpoints = re.findall(r'["\047](/api/[^"\047>\s]+)["\047]', source)
        findings['endpoints'].extend([(source_name, e) for e in endpoints])
        
        # Debug/TODO comments
        comments = re.findall(r'//\s*(TODO|FIXME|HACK|DEBUG|XXX|VULN)[^\n]*', source, re.I)
        findings['comments'].extend([(source_name, c) for c in comments])
        
        # Debug code (console.log, debugger statements)
        debug_lines = re.findall(r'console\.(log|debug|warn|error)\([^)]+\)', source)
        if len(debug_lines) > 10:
            findings['debug_code'].append((source_name, len(debug_lines)))
    
    return findings

# Usage:
findings = analyze_sourcemap('app.js.map')
print(f"Secrets: {len(findings['secrets'])}")
print(f"Endpoints: {len(findings['endpoints'])}")
print(f"Debug comments: {len(findings['comments'])}")
```

---

## Comprehensive JS Analysis Checklist

### Endpoint Discovery
- [ ] Extracted all API URLs from JS files
- [ ] Checked source maps for hidden endpoints
- [ ] Found GraphQL endpoints
- [ ] Found WebSocket endpoints
- [ ] Extracted versioned API paths (/v1/, /v2/, /api/v2/)
- [ ] Extracted WebSocket endpoints
- [ ] Checked fetch/axios calls for hidden API
- [ ] Checked XHR calls in event handlers

### Secret Discovery
- [ ] Ran SecretFinder on all JS files
- [ ] Checked source maps for secrets
- [ ] Looked for AWS keys
- [ ] Looked for GitHub tokens
- [ ] Looked for Stripe/API keys
- [ ] Found JWT tokens in JS
- [ ] Checked for API keys in config objects
- [ ] Checked for database connection strings
- [ ] Checked environment variables (NEXT_PUBLIC_, process.env)

### XSS Analysis
- [ ] Found all innerHTML/outerHTML assignments
- [ ] Found all document.write calls
- [ ] Found all eval() calls
- [ ] Found dangerouslySetInnerHTML (React)
- [ ] Found v-html (Vue)
- [ ] Found [innerHTML] bindings (Angular)
- [ ] Traced source-to-sink for each XSS sink
- [ ] Checked for sanitization bypasses
- [ ] Found postMessage listeners with XSS sinks

### Auth Analysis
- [ ] Found JWT handling code
- [ ] Checked for client-side role checks
- [ ] Found localStorage/sessionStorage token storage
- [ ] Checked for prototype pollution vectors
- [ ] Verified no client-side-only auth
- [ ] Found OAuth token handling
- [ ] Checked for token in URL

### postMessage Analysis
- [ ] Found all postMessage listeners
- [ ] Checked origin validation
- [ ] Checked if message data reaches XSS sinks
- [ ] Checked WebSocket auth

---

## JS Analysis Tools Reference

| Tool | Purpose | Install |
|------|---------|---------|
| jsluice | Endpoint + secret extraction | `go install github.com/eth0izzle/sl0t/jsluice/cmd/jsluice@latest` |
| SecretFinder | Secret scanning | `pip3 install secretfinder` |
| LinkFinder | Endpoint extraction | `pip3 install linkfinder` |
| Retire.js | Vulnerable library detection | `npm3 install retire` |
| js-beautify | Code formatting | `npm3 install js-beautify` |
| Burp JS Miner | JS analysis in Burp | Burp extension |
| Chrome DevTools | Runtime analysis | Built into Chrome |

---

## Common JS Vulnerability Summary

| Vuln Class | Detection | Impact |
|-----------|-----------|--------|
| Client-side auth bypass | Role check in JS only | High |
| Prototype pollution | merge/assign with user input | High |
| postMessage XSS | Listener without origin check | High |
| DOM XSS | innerHTML with user input | High |
| JWT in localStorage | Token accessible via XSS | Medium |
| API keys in JS | Exposed in source | Medium |
| Source map exposure | Original source available | Low-Medium |
| WebSocket no auth | WS connection without auth | Medium |

---

## Final Rule

> **JavaScript is the attack surface of modern web applications. Skip JS analysis and you skip 50% of bugs. Every JS file is a potential goldmine of endpoints, secrets, and vulnerabilities. Analyze every one.**
