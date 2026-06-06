# JavaScript Deobfuscation: Complete Reference

> Comprehensive rules and techniques for reversing JavaScript obfuscation in bug bounty, red-team, and malware-analysis contexts.
> Covers automated tools, manual DevTools workflows, string extraction, control-flow reversal, packer analysis, webpack, and secret hunting.

---

## Table of Contents

1. [Fundamentals & Mindset](#1-fundamentals--mindset)
2. [Minification Reversal](#2-minification-reversal)
3. [String Obfuscation](#3-string-obfuscation)
4. [Array-Based Obfuscation](#4-array-based-obfuscation)
5. [Control Flow Obfuscation](#5-control-flow-obfuscation)
6. [Eval / Function Constructor Deobfuscation](#6-eval--function-constructor-deobfuscation)
7. [Webpack Analysis](#7-webpack-analysis)
8. [Packer Detection & Reversal](#8-packer-detection--reversal)
9. [Automated Tools](#9-automated-tools)
10. [Manual DevTools Workflow](#10-manual-devtools-workflow)
11. [Windows / PowerShell Deobfuscation](#11-windows--powershell-deobfuscation)
12. [Secret Extraction from Deobfuscated Output](#12-secret-extraction-from-deobfuscated-output)
13. [Anti-Tampering & Anti-Debug Bypass](#13-anti-tampering--anti-debug-bypass)
14. [Real-World Workflows](#14-real-world-workflows)

---

## 1. Fundamentals & Mindset

### 1.1 Why JS is obfuscated
- **Bug bounty targets**: hide API endpoints, auth logic, secret keys embedded in SPAs
- **Malware / phishing**: evade signature detection, hide C2 URLs, payload extraction
- **Anti-tampering**: prevent casual modification of client-side logic
- **Intellectual property**: protect proprietary algorithms (e.g., trading bots, game logic)

### 1.2 Before you start
```
RULE 1: Never run obfuscated JS you haven't reviewed.
  - Run in isolated VM / sandbox / browser dev tools with network throttled
  - Use Node.js with --inspect in a disposable container
  - Disable localStorage / sessionStorage / cookies when executing unknown code

RULE 2: Always search decoded strings for secrets immediately.
  - API keys, JWT tokens, internal URLs, hardcoded passwords
  - Regex patterns for base64, hex, URL-encoded strings

RULE 3: Capture the original file before any transformation.
  - Save source + line count + hash for reproducibility
  - Version every deobfuscation step
```

### 1.3 The deobfuscation pyramid
```
      Level 0: Readable source (target)
      Level 1: Minified but structurally intact
      Level 2: String-obfuscated (arrays, encoding)
      Level 3: Control-flow flattened / opaque predicates
      Level 4: Self-modifying / polymorphic / virtualized
      Level 5: JIT-compiled / WASM-based obfuscation
```

### 1.4 Toolchain overview
```
  Browser DevTools          -> Quick analysis, runtime decoding
  de4js (online)            -> Automated multi-method unpacking
  jsnice.org                -> Variable renaming + type inference
  jstools (npm)             -> AST-based transformations
  node.js + custom scripts  -> Heavy lifting for large payloads
  Burp / ZAP extender       -> Intercept + deobfuscate in proxy
```

---

## 2. Minification Reversal

### 2.1 Identifying minification
Minified JS removes whitespace, shortens variable names, and strips comments. It is NOT obfuscation but often precedes it.

Signs:
```
- Single line or minimal line breaks
- Variable names: a, b, c, _0x123, $, $$
- No meaningful comments
- Functions chained without spacing
- Source map comment may exist (//# sourceMappingURL=)
```

### 2.2 Prettier (recommended)
```
# Install globally
npm install -g prettier

# Basic formatting
npx prettier --write obfuscated.js --tab-width 2 --single-quote

# Output to stdout (preserve original)
npx prettier obfuscated.js --tab-width 4 2>nul | clip

# With specific parser
npx prettier obfuscated.js --parser babel --tab-width 2

# Windows PowerShell
$js = Get-Content -Raw "obfuscated.js"
$js | npx prettier --stdin-filepath "dummy.js" --tab-width 2
```

### 2.3 js-beautify
```
# Install
npm install -g js-beautify

# Basic usage
js-beautify obfuscated.js -o beautified.js

# With options
js-beautify obfuscated.js --indent-size 2 --indent-char space --wrap-line-length 120

# PowerShell pipeline
Get-Content -Raw obfuscated.js | js-beautify --stdin
```

### 2.4 VS Code built-in formatter
```
1. Open obfuscated.js in VS Code
2. Select all (Ctrl+A)
3. Format Document (Shift+Alt+F)
4. Use JS/TS formatter (Prettier extension)
```

### 2.5 Minified code before / after
Before (minified):
```js
function a(b,c){return b+c}var x=a(1,2);console.log(x);
```

After (Prettier):
```js
function a(b, c) {
  return b + c;
}
var x = a(1, 2);
console.log(x);
```

### 2.6 Identifying mangled names
Minifiers rename aggressively:
```
Original:  calculateTotal, userData, authenticationToken
Minified: a, b, c, d, e, f, g
```

Manual renaming heuristic:
```
- Single-letter vars near top-level: likely important
- Repeated short names: look for module exports
- Names like _0x....: likely string array index
```

### 2.7 Dealing with source maps
If a sourceMappingURL is present:
```js
//# sourceMappingURL=app.min.js.map
```

Recover original source:
```
# Download map file
curl -O https://target.com/app.min.js.map

# Use source-map module
npm install -g source-map
node -e "
const sm = require('source-map');
const raw = require('fs').readFileSync('app.min.js.map','utf8');
const consumer = new sm.SourceMapConsumer(raw);
consumer.eachMapping(m => console.log(m.generatedLine, m.originalLine, m.name));
"
```

### 2.8 Batch formatting multiple files
```powershell
# PowerShell - process all .js files in directory
Get-ChildItem -Filter "*.js" -Recurse | ForEach-Object {
    $out = "beautified_" + $_.Name
    js-beautify $_.FullName -o ".\beautified\$out"
}
```

---

## 3. String Obfuscation

### 3.1 Hex encoding
Strings encoded as hexadecimal escape sequences.

Pattern:
```js
\x48\x65\x6c\x6c\x6f   // "Hello"
\x68\x74\x74\x70\x3a\x2f\x2f\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d  // "http://example.com"
```

Detection:
```regex
(?:\\x[0-9a-fA-F]{2}){4,}
```

Decoding:

**Node.js one-liner:**
```bash
node -e "console.log(eval('\"\\x48\\x65\\x6c\\x6c\\x6f\"'))"
```

**PowerShell:**
```powershell
$hex = "48 65 6c 6c 6f"
-join ($hex -split ' ' | ForEach-Object { [char][convert]::ToInt16($_, 16) })
```

**Browser console:**
```js
'\x48\x65\x6c\x6c\x6f'
// "Hello"
```

### 3.2 Unicode encoding
Strings encoded as `\uXXXX` sequences.

Pattern:
```js
\u0048\u0065\u006c\u006c\u006f   // "Hello"
\u0073\u0065\u0063\u0072\u0065\u0074  // "secret"
```

Detection:
```regex
(?:\\u[0-9a-fA-F]{4}){3,}
```

Decoding:

**Node.js:**
```bash
node -e "console.log('\u0048\u0065\u006c\u006c\u006f')"
```

**Browser console:**
```js
'\u0048\u0065\u006c\u006c\u006f'
```

**PowerShell regex replacement:**
```powershell
$s = '\u0048\u0065\u006c\u006c\u006f'
$r = [regex]::new('\\u([0-9a-fA-F]{4})')
$r.Replace($s, { param($m) [char][convert]::ToInt16($m.Groups[1].Value, 16) })
```

### 3.3 Base64 encoding
Strings passed through btoa() or Buffer.toString('base64').

Pattern:
```js
atob("SGVsbG8=")                    // "Hello"
Buffer.from("SGVsbG8=", "base64").toString()
btoa("Hello")                        // "SGVsbG8=" (encoding, not obfuscation)
```

Detection:
```regex
atob\(["'`][A-Za-z0-9+/=]{10,}["'`]\)
```

Decoding:

**Browser console:**
```js
atob("SGVsbG8=")
```

**Node.js:**
```bash
node -e "console.log(Buffer.from('SGVsbG8=', 'base64').toString())"
```

**PowerShell:**
```powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("SGVsbG8="))
```

### 3.4 Base64 with custom alphabet / multiple passes
Obfuscators may double-encode or use custom alphabets.

Double-encoded:
```js
atob(atob("U0dWc2JHOD0="))  // "Hello"
```

Decode step by step:
```js
atob("U0dWc2JHOD0=")  // "SGVsbG8="
atob("SGVsbG8=")       // "Hello"
```

### 3.5 ROT13 / Caesar cipher
Simple substitution cipher, often in phishing kits.

Pattern:
```js
"Uryyb".replace(/[a-zA-Z]/g, function(c) {
  return String.fromCharCode(
    c <= "Z" ? ((c.charCodeAt(0) - 65 + 13) % 26) + 65
            : ((c.charCodeAt(0) - 97 + 13) % 26) + 97
  );
});
```

Detection:
```regex
(?:c\.charCodeAt|fromCharCode).*?(?:13|\-13|\+13)
```

Decoding:

**Node.js:**
```bash
node -e "console.log('Uryyb'.replace(/[a-zA-Z]/g,c=>String.fromCharCode(c<='Z'?(c.charCodeAt(0)-65+13)%26+65:(c.charCodeAt(0)-97+13)%26+97)))"
```

### 3.6 XOR encoding
Common in malware JS, C2 payloads.

Pattern:
```js
(function(s, k) {
  var r = "";
  for (var i = 0; i < s.length; i++) {
    r += String.fromCharCode(s.charCodeAt(i) ^ k.charCodeAt(i % k.length));
  }
  return r;
})("encrypted_string", "key");
```

Detection:
```regex
charCodeAt\(.*?\)\s*\^
```

Decoding:

**Node.js:**
```bash
node -e "
function xor(s,k){var r='';for(var i=0;i<s.length;i++){r+=String.fromCharCode(s.charCodeAt(i)^k.charCodeAt(i%k.length));}return r;}
console.log(xor('encrypted_string','key'));
"
```

### 3.7 Char code arrays
Strings built from character codes.

Pattern:
```js
String.fromCharCode(72, 101, 108, 108, 111)   // "Hello"
[72,101,108,108,111].map(x=>String.fromCharCode(x)).join('')
```

Detection:
```regex
fromCharCode\([0-9,\s]{10,}\)
```

Decoding:

**Browser console:**
```js
String.fromCharCode(72, 101, 108, 108, 111)
```

**Node.js:**
```bash
node -e "console.log(String.fromCharCode(...[72,101,108,108,111]))"
```

**PowerShell:**
```powershell
$codes = @(72,101,108,108,111)
-join ($codes | ForEach-Object { [char]$_ })
```

### 3.8 Concatenation splitting
Long strings split into fragments.

Pattern:
```js
var url = "ht" + "tp" + "s:" + "//" + "ex" + "amp" + "le.c" + "om";
```

Detection:
```regex
["'`][a-zA-Z0-9]{1,5}["'`]\s*\+\s*["'`]
```

Deobfuscation: just let Prettier / beautifier join them, or eval at runtime.

### 3.9 Escaped string embedding
Full string embedded with mix of encodings.

Example:
```js
\x48e\x6c\x6co
\u0048ello
```

Manual approach: concatenate in console and read result.

---

## 4. Array-Based Obfuscation

### 4.1 String array pattern
The most common commercial obfuscator pattern. A large array holds all strings, accessed by index.

Pattern:
```js
var _0xabc = ["Hello", "World", "secret", "https://api.example.com"];
(function(_0x1, _0x2) {
  // shift / rotate logic
})(_0xabc);

function _0x123(_0x4, _0x5) {
  return _0xabc[_0x4];
}
```

Usage in code:
```js
var msg = _0x123(0);  // "Hello"
var url = _0x123(3);  // "https://api.example.com"
```

### 4.2 Extracting the string array
Step 1: Locate the array definition (usually top of file).
Step 2: Copy array contents.
Step 3: Map indexes to values.

**Browser console method:**
```js
// Find the array variable
var arr = _0xabc;  // Replace with actual variable name
console.log(arr);
// Iterate all entries
arr.forEach(function(v, i) {
  console.log(i + ": " + v);
});
```

**Node.js extraction script:**
```bash
node -e "
// Paste array definition
var _0xabc = ['Hello','World','secret','https://api.example.com'];
_0xabc.forEach((v,i) => console.log(i + ' -> ' + v));
"
```

### 4.3 Array rotation / self-modifying arrays
Obfuscators often rotate array elements:
```js
(function(arr, count) {
  while (count--) {
    arr.push(arr.shift());
  }
})(_0xabc, 57);
```

This rotates the array 57 times. To get correct mappings, you must either:
1. Run the rotation in JS
2. Reverse rotate when extracting

**Solution: Let the code rotate itself:**
```js
// Copy the exact rotation code + array definition
// Execute in console, then dump rotated array
console.log(_0xabc);
```

### 4.4 Array with string splitting inside accessor
```js
var _0x1234 = ["he", "llo", "wo", "rld"];
function _0xget(a, b) {
  return _0x1234[a] + _0x1234[b];
}
// _0xget(0,1) -> "hello"
```

Detection:
```regex
_\w+\[\d+\]\s*\+\s*_\w+\[\d+\]
```

### 4.5 Automated array extraction with node
For large arrays (1000+ entries), write a script:

```javascript
// extract-array.js
const fs = require('fs');
const vm = require('vm');

// Read obfuscated file
const code = fs.readFileSync('obfuscated.js', 'utf8');

// Extract array definition using regex
const arrMatch = code.match(/var\s+(\w+)\s*=\s*\[([^\]]+)\];/);
if (arrMatch) {
  const varName = arrMatch[1];
  const arrContent = arrMatch[2];
  
  // Safely parse array
  const arr = eval('[' + arrContent + ']');
  
  // Write mapping
  let output = '';
  arr.forEach((v, i) => {
    output += `${i}\t${v}\n`;
  });
  fs.writeFileSync('array-dump.tsv', output);
  console.log(`Extracted ${arr.length} strings to array-dump.tsv`);
}
```

### 4.6 Replacing array references with actual strings
After you have the decoded array, rebuild the source:

```bash
node -e "
const fs = require('fs');
let code = fs.readFileSync('obfuscated.js', 'utf8');

// Paste the decoded array mapping
const map = {
  '0': '\"Hello\"',
  '1': '\"World\"',
  '3': '\"https://api.example.com\"'
};

// Replace _0xabc(X) with actual string
for (const [idx, str] of Object.entries(map)) {
  const regex = new RegExp('_0xabc\\(' + idx + '\\)', 'g');
  code = code.replace(regex, str);
}

fs.writeFileSync('deobfuscated.js', code);
console.log('Done');
"
```

### 4.7 String array with index obfuscation
Indexes may be computed, not literal:
```js
_0xabc[3 * 7 - 20]  // index 1
_0xabc[0xFF & 0x101] // index 1
```

These evaluate to constants. Run in console to resolve:
```js
console.log(3 * 7 - 20);  // 1
console.log(0xFF & 0x101); // 1
```

### 4.8 Nested array access
```js
var _0xarr = [["Hello", "World"], ["secret", "key"]];
_0xarr[0][1]  // "World"
_0xarr[1][0]  // "secret"
```

Dump as flat list:
```js
function flatten(arr) {
  return arr.reduce((acc, val) => acc.concat(Array.isArray(val) ? flatten(val) : val), []);
}
console.log(flatten(_0xarr));
```

---

## 5. Control Flow Obfuscation

### 5.1 Opaque predicates
Always-true or always-false conditions that confuse static analysis.

Pattern:
```js
if ("someStaticString".length === 14) {  // always true
  realCode();
}
if (1 === 2) {  // always false
  // dead code - can be removed
  fakeCode();
}
```

Detection:
```regex
if\s*\(["'].*?["']\.length\s*===?\s*\d+\)
```

Deobfuscation:
- Identify always-true / always-false conditions
- Remove dead branches
- Inline live branches

**Automated removal with Node:**
```bash
node -e "
const fs = require('fs');
let code = fs.readFileSync('obfuscated.js', 'utf8');

// Remove if(1===2){...} or similar impossible conditions
code = code.replace(/if\s*\(\d+\s*===\s*\d+[^)]*\)\s*\{[^}]*\}/g, '');
// Remove if(false){...}
code = code.replace(/if\s*\(!1\)\s*\{[^}]*\}/g, '');
// Replace if(true){...} with just the body
code = code.replace(/if\s*\(!0\)\s*\{([^}]*)\}/g, '$1');

fs.writeFileSync('cleaned.js', code);
"
```

### 5.2 Control flow flattening
The most destructive form. Uses a switch-case dispatcher to break linear code flow.

Pattern:
```js
var state = 5;
while (true) {
  switch (state) {
    case 5:
      // do something
      state = 3;
      break;
    case 3:
      // do something else
      state = 7;
      break;
    case 7:
      // finalize
      state = -1;
      break;
    default:
      break;
  }
  if (state === -1) break;
}
```

Detection:
```regex
while\s*\(\s*(?:true|1)\s*\)\s*\{[\s\S]*?switch\s*\(
```

### 5.3 Deobfuscating control flow flattening
Manual approach:
1. Map each state number to its code block
2. Follow the state transitions
3. Reconstruct linear order

For simple flattening, create a state map:
```js
// States as observed:
// 5 -> 3 -> 7 -> -1 (exit)
// Reconstructed order:
// Block for state 5 (first)
// Block for state 3 (second)
// Block for state 7 (third)
```

### 5.4 Split dispatcher / multiple state variables
Advanced flattening uses multiple state variables or computed states:
```js
var state = 42;
var state2 = 0;
while (true) {
  state = state ^ state2;
  switch (state) {
    // ...
  }
}
```

Solution: execute the code step by step in a debugger, logging state transitions.

### 5.5 Dead code insertion
Obfuscators insert unreachable code to waste analyst time.

Pattern:
```js
function realFunc() {
  // real logic
}
function _0xdead() {
  // never called - fake function
  var a = 1 + 2;
  console.log("fake");
}
```

Detection:
- Functions not referenced anywhere
- Code inside `if(false)` or `if(neverTrue)`
- Extra switch cases not reachable

### 5.6 Call stack obfuscation
Indirect calls via array of functions:
```js
var fnArr = [funcA, funcB, funcC];
fnArr[someState]();
```

Resolution: log which index is called with what arguments.

### 5.7 Property access obfuscation
```js
var obj = {};
obj["\x73\x65\x63\x72\x65\x74"] = "value";
// Equivalent to: obj.secret = "value"
```

---

## 6. Eval / Function Constructor Deobfuscation

### 6.1 Direct eval
```js
eval("alert('Hello')");
var code = "console.log('decoded')";
eval(code);
```

Detection:
```regex
eval\s*\(
```

### 6.2 Indirect eval
```js
(0, eval)("code here");
window.eval("code here");
var e = eval; e("code");
```

Detection:
```regex
\(0,\s*eval\)
```

### 6.3 Function constructor
```js
var f = new Function("a", "b", "return a + b");
f(1, 2);

var f2 = Function("return 'decoded'")();

// Commonly used to decode strings:
var decoded = Function("return " + someEncodedString)();
```

Detection:
```regex
new\s+Function|Function\s*\(
```

### 6.4 setTimeout / setInterval string eval
```js
setTimeout("alert('Hello')", 1000);
setInterval("someCode()", 500);
```

Detection:
```regex
setTimeout\s*\(\s*["'`]
```

### 6.5 Extracting eval content
**Browser console method:**
```js
// Override eval to capture code
var originalEval = window.eval;
window.eval = function(code) {
  console.log("EVAL:", code);
  debugger;  // pause execution
  return originalEval(code);
};
```

**Node.js method:**
```javascript
// capture-eval.js
const vm = require('vm');
const fs = require('fs');

const code = fs.readFileSync('obfuscated.js', 'utf8');

// Create sandbox that logs eval calls
const sandbox = {
  console: console,
  eval: function(c) {
    console.log("=== EVAL CALLED ===");
    console.log(c);
    console.log("=== END EVAL ===");
    return vm.runInThisContext(c);
  },
  setTimeout: function(fn, ms) {
    if (typeof fn === 'string') {
      console.log("=== setTimeout STRING ===");
      console.log(fn);
    }
  }
};

vm.createContext(sandbox);
vm.runInContext(code, sandbox);
```

### 6.6 Recursive eval chains
Some obfuscation nests eval calls:
```js
eval(eval(eval("...decoded_string...")))
```

Solution: evaluate one level at a time until plain code emerges.

### 6.7 The eval replacement technique
Replace `eval(...)` with `console.log(...)`:

```javascript
// Replace eval with console.log to capture output
let code = obfuscatedCode;
code = code.replace(/eval\s*\(/g, 'console.log(');
// Then run in Node - the decoded code will be printed instead of executed
```

### 6.8 Using vm module to catch eval output
```bash
node -e "
const vm = require('vm');
const fs = require('fs');
const code = fs.readFileSync('obfuscated.js', 'utf8');

// Patch Function constructor
const context = {
  console: console,
  Function: function() {
    const args = Array.from(arguments);
    const body = args.pop();
    console.log('=== Function body ===');
    console.log(body);
    return function() {};
  },
  setTimeout: function(f) {
    if (typeof f === 'string') console.log('setTimeout:', f);
  }
};
context.Function.prototype = Function.prototype;
vm.createContext(context);
vm.runInContext(code, context);
"
```

### 6.9 Self-evaluating arrays
Pattern:
```js
[function() {
  return "decoded";
}][0]()
```

This is just an IIFE in array form.

---

## 7. Webpack Analysis

### 7.1 Identifying webpack bundles
Signs:
```js
/******/ (function(modules) { // webpackBootstrap
/******/   // The module cache
/******/   var installedModules = {};
/******/   // The require function
/******/   function __webpack_require__(moduleId) {
/******/     // ...
/******/   }
/******/   return __webpack_require__(0);
/******/ })
```

The modules array contains all source files concatenated.

### 7.2 The module map
Structure:
```js
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {
    // module 0 code
/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {
    // module 1 code
/***/ }),
]);
```

### 7.3 Extracting individual modules
**Node.js extraction:**
```javascript
// extract-webpack.js
const fs = require('fs');
const code = fs.readFileSync('bundle.js', 'utf8');

// Find the modules array
const start = code.indexOf('function(__webpack_require__)');
// This is heuristic - actual extraction requires parsing the array

// Better: run the bundle and capture module exports
const vm = require('vm');
const sandbox = {
  console: console,
  module: { exports: {} },
  exports: {}
};
vm.createContext(sandbox);
vm.runInContext(code, sandbox);
```

### 7.4 Finding entry point
The entry module (usually index 0) contains
`__webpack_require__(0)` or similar.

To find which module contains specific code:
```js
// In browser console, after webpack loads:
// Access module cache
var modules = __webpack_modules__ || webpackJsonp;
console.log(Object.keys(modules));
```

### 7.5 Webpack chunk loading
```js
__webpack_require__.e = function(chunkId) {
  // Load chunk via JSONP
  var script = document.createElement('script');
  script.src = chunkId + ".chunk.js";
  document.head.appendChild(script);
};
```

Dynamic chunks are loaded async. To capture them, use network log in DevTools.

### 7.6 Reversing webpack exports
```js
// Module definition pattern
function(module, __webpack_exports__, __webpack_require__) {
  __webpack_exports__["default"] = someValue;
  __webpack_exports__["secret"] = function() { ... };
}
```

Extract exports:
```js
// After bundle runs in Node
Object.keys(sandbox.module.exports);
console.log(sandbox.module.exports.default);
```

### 7.7 Webpack with obfuscation
Many SPA obfuscators target the webpack runtime specifically:
- Obfuscate module contents
- Obfuscate `__webpack_require__` calls
- String-encode module names

Approach:
1. Find the modules array
2. Extract each module function body
3. Run each through Prettier + string decoder
4. Reconstruct meaningful source

### 7.8 Automated webpack deobfuscation
```bash
# Install webpack-source-map
npm install -g webpack-source-map

# Attempt to rebuild
npx webpack-source-map rebuild bundle.js -o output/
```

### 7.9 Source map recovery in webpack
Webpack often emits `.js.map` files alongside bundles.

```bash
# If map exists, recover full source
npm install -g source-map
node -e "
const sourceMap = require('source-map');
const fs = require('fs');
const rawMap = JSON.parse(fs.readFileSync('bundle.js.map', 'utf8'));
const consumer = new sourceMap.SourceMapConsumer(rawMap);
consumer.sources.forEach(s => {
  const content = consumer.sourceContentFor(s);
  if (content) fs.writeFileSync(s.replace(/^webpack:\/\//g,'').replace(/[\/\\]/g,'_'), content);
});
"
```

---

## 8. Packer Detection & Reversal

### 8.1 JSFuck
Brainfuck-style obfuscation using only `[]()!+` characters.

Pattern:
```js
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+...
```

Detection:
```regex
^[\[\]\(\)\!\+]+$
```

Deobfuscation:
```
# Use de4js online: https://lelinhtinh.github.io/de4js/
# Or Node.js module
npm install -g jsfuck
node -e "console.log(require('jsfuck').decode('...jsfuck_code...'))"
```

### 8.2 aaencode
Uses only `a-zA-Z` characters (Japanese-style emoticon encoding).

Pattern:
```js
ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻   // beforeaaencode
```

Detection:
```regex
ﾟωﾟﾉ|｀ｍ´|ゝ｀ノ
```

Deobfuscation:
```
Use de4js: https://lelinhtinh.github.io/de4js/
```

### 8.3 javascript-obfuscator (commercial)
The most common commercial-grade obfuscator. Features:
- String array with rotation
- Control flow flattening
- Opaque predicates
- Identifiers renaming
- Dead code injection
- Domain lock
- Self-defending

Detection:
```regex
_0x[a-f0-9]{4,6}\b
```

Look for:
```js
var _0x1234 = _0x1234 || function() {
  // initializer
};
```

### 8.4 Packer by Dean Edwards
Classic packer format:
```js
eval(function(p,a,c,k,e,d){...}('string|split|by|pipes',62,4,'...'.split('|')))
```

Detection:
```regex
eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)
```

Deobfuscation:
```
# Just run the packed code in a sandbox (the eval will print the result)
# Or use: https://matthewfl.com/unPacker.html
```

### 8.5 Packer reversal with Node
```javascript
// dean-edwards-unpack.js
const fs = require('fs');
const vm = require('vm');

const code = fs.readFileSync('packed.js', 'utf8');

// Find and extract the packed payload
const match = code.match(/eval\(function\(p,a,c,k,e,d\)\{[^}]+}\(([^)]+)\)\)/);
if (match) {
  const packed = 'function(p,a,c,k,e,d){' + code.split('function(p,a,c,k,e,d){')[1];
  // Rebuild unpacker
  const unpacked = vm.runInNewContext('(' + packed + ')');
  console.log(unpacked);
}
```

### 8.6 Obfuscator.io detection
```regex
String\.fromCharCode\(.*?\)|_0x[a-f0-9]+\(0x[a-f0-9]+.*?
```
Specific markers:
```js
var _0x[0-9a-f]+ = _0x[0-9a-f]+
(function(_0x[a-f0-9]+, _0x[a-f0-9]+) {
  // string array rotate
})
```

### 8.7 Self-defending code
Some packs detect modification:
```js
function _0xselfdefend() {
  if (typeof document !== 'undefined' && document.getElementById('deobfuscated')) {
    throw new Error('Tampered');
  }
}
```

Bypass: override the defense function before it runs:
```js
// In console before execution
_0xselfdefend = function() { return true; };
```

### 8.8 Domain lock
Code only runs on specific domain:
```js
if (window.location.hostname !== "example.com") {
  throw new Error("Invalid domain");
}
```

Bypass: override location:
```js
// In browser console before execution
Object.defineProperty(window, 'location', {
  get: function() { return { hostname: 'example.com' }; }
});
```

---

## 9. Automated Tools

### 9.1 de4js
URL: https://lelinhtinh.github.io/de4js/

Capabilities:
- Unpack JSFuck, aaencode, JJencode, etc.
- Decode string arrays
- Unpack Dean Edwards packer
- Remove control flow flattening (basic)
- Beautify output

Usage: Paste code, click Deobfuscate. Iterate if needed.

### 9.2 jsnice.org
URL: http://jsnice.org/

Renames variables based on type inference and usage context.

Example:
```js
// Input
function _0x1a2b(_0x3c4d) {
  return _0x3c4d * 2;
}

// Output
function calculateDouble(value) {
  return value * 2;
}
```

Usage:
1. Paste code
2. Click "Nice"
3. Review renamed output
4. Download result

### 9.3 de4js CLI (Node)
```bash
# Install
npm install -g de4js

# Run
de4js obfuscated.js -o output.js

# With options
de4js obfuscated.js --beautify --eval --array
```

### 9.4 JStillery
URL: https://mindedsecurity.github.io/jstillery/

Advanced deobfuscation with AST manipulation.

### 9.5 UnPacker (Chrome extension)
Various Chrome extensions exist:
- "Javascript Deobfuscator"
- "JS Deobfuscator UnPacker"

### 9.6 Burp Suite extensions
- **JS Beautifier**: automatically beautifies JS responses
- **HackBack**: automatic deobfuscation in proxy

### 9.7 Custom AST manipulation with Babel
```bash
npm install @babel/core @babel/parser @babel/traverse @babel/types @babel/generator
```

Example: replace all string references with decoded values:
```javascript
// babel-deobfuscate.js
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;
const fs = require('fs');

const code = fs.readFileSync('obfuscated.js', 'utf8');
const ast = parser.parse(code, { sourceType: 'script' });

const stringMap = {
  '_0x1234(0)': '"Hello"',
  '_0x1234(1)': '"World"'
};

traverse(ast, {
  CallExpression(path) {
    const name = generate(path.node).code;
    if (stringMap[name]) {
      path.replaceWith(parser.parse(stringMap[name]).program.body[0].expression);
    }
  }
});

const output = generate(ast, { compact: false }).code;
fs.writeFileSync('deobfuscated.js', output);
```

### 9.8 JSNice CLI
```bash
# No official CLI, but you can use the API
curl -X POST -H "Content-Type: application/json" \
  -d '{"code": "function _0x1a(x){return x+1}", "language": "JAVASCRIPT"}' \
  https://jsnice.org/renaming
```

### 9.9 Online playgrounds for quick work
- https://beautifier.io/
- https://lelinhtinh.github.io/de4js/
- https://matthewfl.com/unPacker.html
- https://www.dcode.fr/javascript-unobfuscator

---

## 10. Manual DevTools Workflow

### 10.1 Setting breakpoints on eval
```js
// In Sources tab, create a snippet or use console:
// Override eval to break on call
var _origEval = eval;
eval = function(code) {
  debugger;
  return _origEval(code);
};
```

### 10.2 Override functions to capture output
```js
// Override any function that receives decoded data
var _origFetch = window.fetch;
window.fetch = function(url, opts) {
  console.log("FETCH:", url, opts);
  debugger;
  return _origFetch.apply(this, arguments);
};

var _origXHR = XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open = function(method, url) {
  console.log("XHR:", method, url);
  debugger;
  return _origXHR.apply(this, arguments);
};
```

### 10.3 Using console.log injection
Add `console.log()` before critical function calls:
```js
// In Sources tab, local override
// Find the line, right-click, add logpoint
console.log('decoded string:', decodedValue)
```

Logpoints don't pause execution but log values.

### 10.4 Pretty-print in DevTools
```
1. Open Sources tab
2. Find obfuscated JS file
3. Click { } (Pretty Print) at bottom
```

This is the fastest first step.

### 10.5 Blackboxing framework code
In DevTools > Settings > Blackboxing:
```
Add patterns like:
  jquery\.min\.js
  \.min\.js
  /vendor/
```

This hides third-party code from stack traces.

### 10.6 Using conditional breakpoints
```js
// In Sources tab, right-click line number
// Add conditional breakpoint:
this._0xsecret && this._0xsecret.length > 10
```

### 10.7 Watch expressions for decoding
Add to Watch panel:
```js
_0xabc[0]
_0xget(1, 2)
String.fromCharCode(72,101,108,108,111)
```

### 10.8 Copying decoded strings from console
```js
// Copy array contents as TSV
copy(_0xabc.join('\n'));
// This copies to clipboard in DevTools
```

### 10.9 Using snippets for repeatable deobfuscation
DevTools > Sources > Snippets > New snippet:
```js
// deobfuscate-snippet.js
(function() {
  // Paste array definition here
  
  // Replace all _0x1234(X) patterns
  var code = document.body.innerText;
  // ... process ...
  console.log(code);
})();
```

### 10.10 Network tab filtering
Filter for:
```
- .js (JS files)
- .chunk.js (webpack chunks)
- .map (source maps)
- type:script
```

### 10.11 Replay XHR with modified response
```
1. Network tab > Find JS file
2. Right-click > Copy > Copy as cURL
3. Save response locally
4. Modify, then serve locally with `npx serve`
5. Use Overrides or Requestly to redirect
```

### 10.12 Local overrides in DevTools
```
1. Sources tab > Overrides
2. Select folder for overrides
3. Navigate to JS file
4. Edit directly, Ctrl+S saves
5. On page reload, override is used
```

### 10.13 Debugger evasion detection
If page detects DevTools:
```js
// Anti-debug timing check
setInterval(function() {
  var start = performance.now();
  debugger;
  var end = performance.now();
  if (end - start > 100) {
    // DevTools detected
    window.location = 'about:blank';
  }
}, 1000);
```

Bypass:
```
1. Deactivate breakpoints (Deactivate breakpoints button)
2. Use conditional breakpoint with false condition
3. Right-click line > Never pause here
4. Use DevTools on separate Chrome instance with --remote-debugging-port
```

### 10.14 Anti-debug with DevTools detection
```js
if (/Chrome/.test(navigator.userAgent) && /Google Inc/.test(navigator.vendor)) {
  // Likely DevTools
}
```

Bypass: override navigator properties before page loads.

---

## 11. Windows / PowerShell Deobfuscation

### 11.1 PowerShell method for base64 decode
```powershell
# Standard base64
$s = "SGVsbG8gV29ybGQ="
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))

# URL-safe base64
$s = "SGVsbG8gV29ybGQ"
$padded = $s
switch ($s.Length % 4) {
  2 { $padded = $s + "==" }
  3 { $padded = $s + "=" }
}
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($padded))
```

### 11.2 PowerShell for hex decode
```powershell
# Hex string to text
$hex = "48656C6C6F"
$bytes = for ($i = 0; $i -lt $hex.Length; $i += 2) {
    [convert]::ToByte($hex.Substring($i, 2), 16)
}
[System.Text.Encoding]::UTF8.GetString($bytes)

# From hex with spaces
$hexWithSpaces = "48 65 6C 6C 6F"
$bytes = $hexWithSpaces -split ' ' | ForEach-Object { [convert]::ToByte($_, 16) }
[System.Text.Encoding]::UTF8.GetString($bytes)
```

### 11.3 PowerShell for char codes
```powershell
$codes = @(72, 101, 108, 108, 111)
-join ($codes | ForEach-Object { [char]$_ })
```

### 11.4 PowerShell to deobfuscate a JS file
```powershell
# Read obfuscated JS
$content = Get-Content -Raw "obfuscated.js"

# Extract all hex-encoded strings and decode
$hexPattern = '\\x([0-9a-fA-F]{2})'
$decoded = [regex]::Replace($content, $hexPattern, {
    param($m)
    [char][convert]::ToInt16($m.Groups[1].Value, 16)
})

# Extract all unicode-encoded strings
$uniPattern = '\\u([0-9a-fA-F]{4})'
$decoded = [regex]::Replace($decoded, $uniPattern, {
    param($m)
    [char][convert]::ToInt16($m.Groups[1].Value, 16)
})

$decoded | Out-File "partially_decoded.js"
```

### 11.5 PowerShell to extract string arrays
```powershell
# Find array definitions and dump them
$content = Get-Content -Raw "obfuscated.js"

# Match var _0x... = ["item1","item2",...]
$pattern = 'var\s+(\w+)\s*=\s*\[([^\]]+)\]'
$matches = [regex]::Matches($content, $pattern)

foreach ($match in $matches) {
    $varName = $match.Groups[1].Value
    $arrayContent = $match.Groups[2].Value

    # Parse array content (simplified - doesn't handle nested)
    $items = $arrayContent -split ','
    Write-Host "Array: $varName ($($items.Length) items)"
    for ($i = 0; $i -lt $items.Length; $i++) {
        Write-Host "  [$i] = $($items[$i])"
    }
}
```

### 11.6 PowerShell equivalent of Node eval decoding
```powershell
# For simple expressions, use iex (Invoke-Expression) carefully
# WARNING: Only use on trusted content
$encoded = '"' + '\x48\x65\x6c\x6c\x6f' + '"'
$decoded = Invoke-Expression $encoded
Write-Host $decoded
```

### 11.7 Download obfuscated JS via PowerShell
```powershell
# Download JS files for offline analysis
Invoke-WebRequest -Uri "https://target.com/assets/app.abc123.js" -OutFile "obfuscated.js"

# With cookie/auth if needed
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$cookie = New-Object System.Net.Cookie("session", "your_session_value", "/", "target.com")
$session.Cookies.Add($cookie)
Invoke-WebRequest -Uri "https://target.com/assets/app.abc123.js" `
  -WebSession $session `
  -OutFile "obfuscated.js"
```

### 11.8 PowerShell to search for secrets in JS
```powershell
$content = Get-Content -Raw "obfuscated.js"

# Search for potential secrets
$patterns = @(
    'api[_-]?key["\s:=]+["\']([^"\']+)["\']',
    'sk-[a-zA-Z0-9]{20,}',
    'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'AKIA[0-9A-Z]{16}',
    'https?://[^\s"\'`]+\.(com|net|org|io|app)[^\s"\'`]*',
    '["\'](?:https?://internal|https?://10\.|https?://192\.168)'
)

foreach ($pattern in $patterns) {
    $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($match in $matches) {
        Write-Host "Found [$pattern]: $($match.Value)"
    }
}
```

### 11.9 Using Node.js from PowerShell
```powershell
# Install Node.js if not present
# Then run scripts
node -e @"
const fs = require('fs');
const code = fs.readFileSync('obfuscated.js', 'utf8');
// Process here
console.log(code.substring(0, 1000));
"@
```

### 11.10 Process JS with local HTTP server
```powershell
# Serve obfuscated file locally to inspect in browser
# Install http-server
npm install -g http-server

# Create a simple HTML wrapper
@"
<html><body>
<script>
$(Get-Content -Raw "obfuscated.js")
console.log('Array dump:', _0xabc);
</script></body></html>
"@ | Out-File "debug.html"

# Serve and open
http-server -p 8080
Start-Process "http://localhost:8080/debug.html"
```

### 11.11 Windows batch deobfuscation wrapper
```batch
@echo off
rem deobfuscate.bat
node -e "console.log(eval('\"%1\"'))"
```

Usage:
```batch
deobfuscate.bat \x48\x65\x6c\x6c\x6f
```

### 11.12 Decoding common phishing JS patterns
Phishing kits often use:
```powershell
# Charcode array decode (common in phishing)
$s = @(99,114,101,100,101,110,116,105,97,108,115)
-join ($s | ForEach-Object { [char]$_ })

# Rot13 decode
function Invoke-Rot13($s) {
    $r = ""
    foreach ($c in $s.ToCharArray()) {
        if ($c -ge 'a' -and $c -le 'z') {
            $r += [char]([int][math]::Floor(($c - 97 + 13) % 26) + 97)
        } elseif ($c -ge 'A' -and $c -le 'Z') {
            $r += [char]([int][math]::Floor(($c - 65 + 13) % 26) + 65)
        } else {
            $r += $c
        }
    }
    return $r
}
Invoke-Rot13 "Uryyb Jbeyq"
```

### 11.13 Extracting URLs from deobfuscated output
```powershell
$content = Get-Content -Raw "output.js"

# URL extraction
$urlPattern = 'https?://[^\s"\'`<>]+'
$urls = [regex]::Matches($content, $urlPattern)
$urls | ForEach-Object { $_.Value } | Sort-Object -Unique

# Save to file
$urls | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "extracted_urls.txt"
```

### 11.14 File monitoring for JS changes
```powershell
# Monitor JS file for changes during dynamic analysis
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "."
$watcher.Filter = "*.js"
$watcher.EnableRaisingEvents = $true

Register-ObjectEvent $watcher "Changed" -Action {
    Write-Host "File changed: $($Event.SourceEventArgs.FullPath)"
    Get-Content -Raw $Event.SourceEventArgs.FullPath | Out-File "last_change.js"
}

# Wait for changes
Write-Host "Watching for JS changes... (Ctrl+C to stop)"
while ($true) { Start-Sleep -Seconds 1 }
```

---

## 12. Secret Extraction from Deobfuscated Output

### 12.1 API keys and tokens
After deobfuscation, search for:

```regex
# AWS keys
AKIA[0-9A-Z]{16}

# Google API keys
AIza[0-9A-Za-z\-_]{35}

# Stripe
sk_live_[0-9a-zA-Z]{24,}
pk_live_[0-9a-zA-Z]{24,}

# GitHub tokens
ghp_[0-9a-zA-Z]{36}
gho_[0-9a-zA-Z]{36}
ghu_[0-9a-zA-Z]{36}

# Slack tokens
xox[baprs]-[0-9a-zA-Z\-]{10,}

# Discord tokens
[MN][A-Za-z\d]{23,28}\.[A-Za-z\d]{6,7}\.[A-Za-z\d_\-]{27}

# JWT tokens
eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+

# Firebase URLs
https://[a-zA-Z0-9-]+\.firebaseio\.com

# SendGrid
SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{43}

# Mapbox
pk\.[a-zA-Z0-9]{60,}

# Twilio
SK[a-zA-Z0-9]{32}
```

### 12.2 Internal URLs and endpoints
```regex
https?://(?:internal|staging|dev|admin|api-int|jenkins|gitlab)\.\S+
https?://10\.\d+\.\d+\.\d+(?::\d+)?
https?://192\.168\.\d+\.\d+(?::\d+)?
https?://172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+(?::\d+)?
wss?://[^\s"']+
/?(api|v1|v2|rest|graphql|admin|internal|private)/\S*
```

### 12.3 Hardcoded credentials
```regex
["\'][Pp]assword["\']\s*[:=]\s*["\'][^"\']+["\']
["\'][Uu]sername["\']\s*[:=]\s*["\'][^"\']+["\']
["\']secret["\']\s*[:=]\s*["\'][^"\']+["\']
["\'](?:api_key|apikey|api-secret)["\']\s*[:=]\s*["\'][^"\']+["\']
```

### 12.4 JWT inspection
Extract JWT and decode:
```bash
node -e "
const jwt = 'eyJ...'; // paste token
const parts = jwt.split('.');
console.log('Header:', JSON.parse(Buffer.from(parts[0], 'base64url').toString()));
console.log('Payload:', JSON.parse(Buffer.from(parts[1], 'base64url').toString()));
"
```

### 12.5 Source map secrets
Source maps sometimes expose internal comments:
```bash
# Search for TODO, FIXME, hack, password in source map content
node -e "
const fs = require('fs');
const map = JSON.parse(fs.readFileSync('app.js.map','utf8'));
const content = Object.values(map.sourcesContent || {}).join('\n');
const matches = content.match(/TODO|FIXME|password|secret|hack|temporary/gi);
console.log(matches);
"
```

### 12.6 Configuration objects
After deobfuscation, look for:
```js
var config = {
  apiUrl: "https://api.example.com",
  apiKey: "supersecretkey",
  environment: "production"
};
```

Many obfuscators don't fully obfuscate config objects.

### 12.7 Hardcoded debug flags
```js
// Look for these patterns
debug: true
isDevelopment: true
bypassAuth: true
skipValidation: true
adminMode: true
```

### 12.8 Endpoint discovery from fetch/XHR calls
After deobfuscation, grep for fetch and XMLHttpRequest:
```regex
fetch\s*\(\s*["\'`]([^"\'`]+)["\'`]
\.open\s*\(\s*["\'`][A-Z]+["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]
axios\.(get|post|put|delete)\s*\(\s*["\'`]([^"\'`]+)["\'`]
\$\..*\(["\'`]([^"\'`]+)["\'`]
```

### 12.9 GraphQL introspection
SPA bundles often contain hardcoded GraphQL queries:
```regex
query\s+\w+\s*\{|mutation\s+\w+\s*\{
```

Deobfuscation reveals all queries.

### 12.10 WebSocket endpoints
```regex
new\s+WebSocket\s*\(\s*["\'`](wss?://[^"\'`]+)["\'`]
```

### 12.11 PostMessage targets
```regex
\.postMessage\s*\(
```

Reveals communication channels and origin validation (or lack thereof).

### 12.12 Feature flags
```js
// After deobfuscation, look for:
flags: {
  newDashboard: true,
  enableSubscription: false,
  experimentalFeature: true
}
```

### 12.13 Redirect URLs (OAuth)
```regex
redirect_uri\s*[:=]\s*["\'`]([^"\'`]+)["\'`]
```

### 12.14 Third-party embed keys
```regex
google-analytics|gtag|fbq|ga\s*\(|__insp|
app-id|app-secret|client-id|client_secret
```

---

## 13. Anti-Tampering & Anti-Debug Bypass

### 13.1 Integrity checks
Code checks its own hash:
```js
// Compute hash of function body
function integrityCheck() {
  var fn = arguments.callee.toString();
  var hash = hashCode(fn);
  if (hash !== EXPECTED_HASH) throw new Error('Tampered');
}
```

Bypass:
```js
// Override toString to return expected source
integrityCheck.toString = function() {
  return 'function integrityCheck() { return true; }';
};
```

### 13.2 Timer-based checks
```js
setInterval(function() {
  if (document.body.innerHTML.indexOf('deobfuscated') > -1) {
    throw new Error('Tampered');
  }
}, 1000);
```

Bypass: clear intervals:
```js
// Get highest timer ID and clear all
var maxId = setTimeout(function() {}, 0);
for (var i = 1; i <= maxId; i++) {
  clearInterval(i);
  clearTimeout(i);
}
```

### 13.3 Prototype tampering detection
```js
if (Array.prototype.map.toString().indexOf('[native code]') === -1) {
  throw new Error('Native function tampered');
}
```

Bypass: restore native functions before executing:
```js
Array.prototype.map = Array.prototype.__proto__.__lookupGetter__('map');
```

### 13.4 Console.log override detection
```js
if (console.log.toString().indexOf('[native code]') === -1) {
  // Overridden - likely DevTools
}
```

Bypass: don't override, use event listeners instead.

### 13.5 DevTools dimension detection
```js
if (window.outerWidth - window.innerWidth > 160 || window.outerHeight - window.innerHeight > 160) {
  // DevTools open
}
```

Bypass: undock DevTools into separate window.

### 13.6 Debugger statements
```js
setInterval(function() {
  debugger;
}, 100);
```

Bypass:
1. Deactivate breakpoints (Ctrl+F8)
2. Conditional breakpoint on debugger line with false
3. Never pause here

### 13.7 toString validation
```js
// Check if functions have been replaced
var toString = Function.prototype.toString;
if (toString.call(someFunction).indexOf('native') === -1) {
  // Function was replaced
}
```

### 13.8 Domain lock bypass patterns
```js
// Pattern: location.hostname check
var _0xdomain = "expected.com";
if (location.hostname !== _0xdomain) {
  _0xselfDestruct();
}
```

Bypass:
```js
// Before page loads, in console
var _0xselfDestruct = function() {};
// Or override location
```

---

## 14. Real-World Workflows

### 14.1 Workflow A: Phishing kit deobfuscation
```
1. Download phishing HTML/JS
2. Paste into de4js
3. If de4js fails, extract string array manually
4. Search for:
   - Credential exfiltration URLs
   - C2 email addresses
   - Redirect URLs
   - Keylogging code
5. Report findings
```

### 14.2 Workflow B: SPA secret extraction
```
1. Load SPA in browser with DevTools open
2. Network tab > Filter JS
3. Save each JS file locally
4. Prettier each file
5. Search for API keys, URLs in beautified output
6. If obfuscated, identify obfuscation type:
   - String array? Extract and replace
   - Control flow? Skip automated, look for config objects
   - javascript-obfuscator? de4js first pass
7. Re-run secret regex on deobfuscated output
8. Test found secrets against target
```

### 14.3 Workflow C: Malware JS analysis
```
1. Isolate in VM / sandbox
2. Download JS sample
3. Check entropy (high = packed/encrypted)
4. Run strings on binary (if exe/js)
5. de4js unpack
6. Extract C2 URLs
7. Search for encryption keys (XOR keys, RC4 keys)
8. Check for second-stage download
9. Run in sandbox with network monitoring
```

### 14.4 Workflow D: Full manual deobfuscation
```
1. Pretty print (Prettier or js-beautify)
2. Identify obfuscation type
3. Extract string array:
   a. Locate array definition
   b. Run array rotation code in console
   c. Dump all values
4. Replace array references with strings
   (Regex replacement or AST)
5. Remove opaque predicates:
   a. Identify always-true conditions
   b. Inline true branch
   c. Remove false branch
6. Handle control flow flattening:
   a. Map state transitions
   b. Reconstruct sequential order
   c. Replace switch with inline code
7. Handle eval / Function:
   a. Replace eval with console.log
   b. Capture decoded code
   c. Iterate if nested
8. Rename variables (jsnice)
9. Search for secrets
10. Document findings
```

### 14.5 Workflow E: Burp integration
```
1. Burp > Proxy > Options > Response Modification
2. Add rule: if Content-Type contains "javascript"
3. Run through js-beautify
4. Optional: remove eval calls
5. Review modified responses in Burp
```

### 14.6 Workflow F: Automated pipeline
```bash
# pipeline-deobfuscate.sh (PowerShell adaptation)
# Usage: .\deobfuscate.ps1 input.js output.js

param([string]$input, [string]$output)

# Step 1: Beautify
$temp1 = "$env:TEMP\step1_beautified.js"
js-beautify $input -o $temp1

# Step 2: de4js
$temp2 = "$env:TEMP\step2_de4js.js"
de4js $temp1 -o $temp2

# Step 3: Replace eval with console.log
$temp3 = "$env:TEMP\step3_noeval.js"
$content = Get-Content -Raw $temp2
$content = $content -replace 'eval\s*\(', 'console.log('
$content | Out-File $temp3

# Step 4: Execute in Node to capture eval output
$temp4 = "$env:TEMP\step4_decoded.js"
node -e "
const fs = require('fs');
const vm = require('vm');
const code = fs.readFileSync('$temp3', 'utf8');
const output = [];
const sandbox = {
  console: { log: function(x) { output.push(x); } }
};
vm.createContext(sandbox);
try { vm.runInContext(code, sandbox); } catch(e) {}
fs.writeFileSync('$temp4', output.join('\n'));
"

# Step 5: Copy result
Copy-Item $temp4 $output
Write-Host "Output written to $output"
```

### 14.7 Phase-by-phase deobfuscation checklist
```
[ ] Phase 1: Inspect
  [ ] Check file size and line count
  [ ] Run strings for quick analysis
  [ ] Identify obfuscation pattern
  [ ] Check for source map

[ ] Phase 2: Unpack
  [ ] de4js
  [ ] string array extraction
  [ ] eval replacement
  [ ] control flow flattening removal

[ ] Phase 3: Beautify
  [ ] Prettier
  [ ] js-beautify
  [ ] Variable renaming (jsnice)

[ ] Phase 4: Analyze
  [ ] Search for API keys
  [ ] Search for URLs
  [ ] Search for hardcoded strings
  [ ] Identify logic flow
  [ ] Map network calls

[ ] Phase 5: Document
  [ ] Save deobfuscated source
  [ ] List found secrets
  [ ] Note C2 / exfil URLs
  [ ] Describe overall functionality
```

### 14.8 Danger signals (stop and assess)
```
- Code uses WebAssembly (WASM) for core logic
- Code detects sandbox and behaves differently
- Code requires network interaction for decryption
- Code contains polymorphic / self-modifying constructs
- Code uses Proxy objects to intercept all property access
- Code loads additional encrypted chunks dynamically
```

### 14.9 Node.js interactive deobfuscation session
```bash
# Start Node interactive
node

# In Node REPL:
> const fs = require('fs');
> const code = fs.readFileSync('obfuscated.js', 'utf8');
> // Test string array access
> eval(code.slice(0, 200));  // Initialize array
> // Now access array elements
> _0xabc[0]
'Hello'
> _0xabc[1]
'World'
> // Dump all
> _0xabc.forEach((v,i) => console.log(i, v));
```

### 14.10 Browser DevTools full workflow
```
1. Open Chrome DevTools (F12)
2. Go to Sources tab
3. Find the obfuscated JS file in the file tree
4. Click Pretty Print ({}) button
5. Set breakpoints at strategic points:
   - After string array initialization
   - Before fetch/XHR calls
   - In eval callbacks
6. Refresh page to trigger breakpoints
7. In Console, evaluate array contents:
   > _0xabc
   > Object.keys(window._0xabc)
8. Use watch expressions for live values
9. Copy decoded output:
   > copy(decodedString)
10. Save using Overrides or "Save as"
```

### 14.11 Common mistakes
```
- Running eval without sandbox
- Not verifying decoded output
- Missing nested obfuscation layers
- Trusting JSNice variable names blindly
- Not checking for source maps
- Overlooking DOM clobbering
- Assuming all strings decoded
- Modifying file and breaking self-defence
- Not logging state transitions in flattening
- Forgetting to clear timers after analysis
```

### 14.12 Obfuscation type quick reference card
```
| Pattern                    | Type                        | Tool                  |
|----------------------------|-----------------------------|-----------------------|
| [][(![]+[])+...            | JSFuck                      | de4js                 |
| ﾟωﾟﾉ= /｀ｍ´）ﾉ ~┻━┻       | aaencode                    | de4js                 |
| eval(function(p,a,c,k...   | Dean Edwards Packer         | de4js / unPacker      |
| _0x[a-f0-9]{4,6}           | javascript-obfuscator       | de4js + manual        |
| \xHH\xHH                   | Hex escape                  | Prettier / manual     |
| \uHHHH                     | Unicode escape              | Prettier / manual     |
| atob(...)                  | Base64                      | atob() / base64 -d    |
| String.fromCharCode(...)   | Char code array             | fromCharCode()        |
| while(true){switch...      | Control flow flattening     | Manual AST            |
| eval("...")                | Eval                        | console.log replace   |
| Function("return ...")()   | Function constructor        | console.log replace   |
| __webpack_require__        | Webpack bundle              | Module extraction     |
```

### 14.13 Recommended tool installations
```bash
# Must-have
npm install -g prettier
npm install -g js-beatify

# Unpacking
npm install -g de4js

# Analysis
npm install -g jsfuck
npm install -g source-map

# AST manipulation
npm install -g @babel/core @babel/parser @babel/traverse @babel/generator
```

### 14.14 Final verification
After deobfuscation, verify:
```
- File size reduced? (obfuscation adds bloat)
- Strings readable?
- Function names meaningful?
- All eval/Function calls decoded?
- No hex/unicode escapes remaining?
- Regex patterns from section 12 produce matches?
- Network calls identifiable?
```

---

> **Remember**: Deobfuscation is iterative. Each layer reveals the next.
> Never trust the output until you've verified the strings are plaintext
> and all control flow is linear. Document every transformation step.
