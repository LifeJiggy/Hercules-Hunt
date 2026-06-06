---
name: Js-deobfuscation
description: JavaScript deobfuscation and reverse engineering specialist. Covers deobfuscating obfuscated JS (obfuscator.io, javascript-obfuscator, custom packers), AST analysis, string array decoding, control flow flattening reversal, dead code injection removal, debugger/anti-tamper bypass, runtime deobfuscation with Chrome DevTools, and automated deobfuscation tools (synchrony, jsnice, de4js). Use when: analyzing obfuscated JavaScript, reverse engineering malware, unpacking JS bundlers, understanding anti-tamper mechanisms, or extracting hidden logic from JS. Chinese trigger: JS反混淆、JavaScript逆向、解混淆、代码还原、AST分析、反调试
---

# Skill: JS Deobfuscation

Turn obfuscated JavaScript back into readable code.

## Core Concept

Obfuscation ≠ Security. Obfuscation only slows you down.

```
OBFUSCATED JS → UNDERSTAND THE OBFUSCATOR → APPLY DEOBFUSCATION → READABLE CODE
```

The goal is NOT to get perfectly formatted code. The goal is to **understand the logic** — what does it do, where are the endpoints, what are the secrets.

---

## Obfuscation Techniques Overview

| Technique | What It Does | How to Recognize |
|-----------|-------------|------------------|
| String Array Encoding | Strings stored in array, accessed by index | Large array at top, `_0x1234(0)` calls |
| Control Flow Flattening | Logic hidden in switch/case state machine | Single big while loop with switch on state variable |
| Dead Code Injection | Random junk code that never executes | Code that doesn't affect state, random variables |
| Variable Renaming | `a`, `b`, `c`, `_0xabc123` | Meaningless variable names |
| Constant Obfuscation | Math expressions instead of values | `0x1a + 0x2b` instead of `65` |
| Hex/Unicode Encoding | `\x41\x42\x43` or `\u0041\u0042\u0043` | Escaped hex/unicode in strings |
| Base64/Rot13 Encoding | Encoded strings | Long strings ending in `=` or `==` |
| Self-Defending | Code that breaks debuggers | `debugger;` statements, `setInterval` checks |
| Domain Locking | Only runs on specific domain | Domain checks, `document.domain` comparisons |
| Function Wrapping | Functions called via indirect references | `_0x1234 = function(_0x5678) { ... }` |

---

## Tool 1: De4js (Online/CLI Deobfuscator)

### Online (Easiest)

```
URL: https://lelinhtinh.github.io/de4js/
OR: https://deobfuscator.zyin.org/
```

**Steps:**
1. Paste obfuscated code
2. Select obfuscator type (obfuscator.io, javascript-obfuscator, etc.)
3. Click "Beautify" or "Deobfuscate"
4. Review output

**Limitations:** Large files may fail. Code with runtime deobfuscation (eval at runtime) won't deobfuscate fully.

### CLI

```bash
# Install
git clone https://github.com/lelinhtinh/de4js.git
cd de4js

# Run with Node.js
node de4js.js -i obfuscated.js -o deobfuscated.js

# Or use js-beautify
npm3 install js-beautify
cat obfuscated.js | npx js-beautify > beautified.js
```

---

## Tool 2: JSNice (Statistical Deobfuscation)

Uses machine learning to rename variables and infer types.

```
URL: https://www.jsnice.org/
```

```bash
# Or via API
curl -s "http://rest.jsnice.org/beautify?code=$(cat obfuscated.js | base64 -w0)" \
  -H "Content-Type: text/plain" \
  -o deobfuscated.js
```

**Pros:** Renames variables to meaningful names, infers types.
**Cons:** Online only, may have rate limits, large code may fail.

---

## Tool 3: Synchrony (Advanced Deobfuscator)

```bash
# Install
git clone https://github.com/relative/synchrony.git
cd synchrony
npm3 install
npm3 run build

# Run
node dist/cli.js -i obfuscated.js -o deobfuscated.js

# Or use the web UI
npm3 start
# Open http://localhost:3000
```

**What it does:**
- Reverses control flow flattening
- Removes dead code
- Decodes string arrays
- Renames variables
- Inlines functions

---

## String Array Decoding (Most Common Obfuscation)

### Pattern Recognition

```javascript
// Typical obfuscated string array
var _0x5a3f = ['api/v2/users', 'Authorization', 'Bearer eyJ...', 'https://target.com'];
var _0x2b1c = function(_0x5a3f, _0x2b1c) {
    _0x5a3f = _0x5a3f - 0x1a2;
    var _0x2b1c = _0x5a3f[_0x2b1c];
    return _0x2b1c;
};
// Usage: _0x2b1c('0x1a3') returns 'api/v2/users'
```

### Automated String Array Decoder

```javascript
// Step 1: Copy the array and accessor function
// Step 2: Paste into this template and run with Node:

const _0x5a3f = ['api/v2/users', 'Authorization', 'Bearer eyJ...', 'https://target.com'];
const _0x2b1c = function(_0x5a3f, _0x2b1c) {
    _0x5a3f = _0x5a3f - 0x1a2;
    return _0x5a3f[_0x2b1c];
};

// Step 3: Replace all _0x2b1c(0x...) calls with actual values
// Use regex: _0x2b1c\('0x([0-9a-fA-F]+)'\)
// Evaluate: parseInt('0x...', 16) - 0x1a2 → index

// Automated replacement:
const code = `... paste obfuscated code here ...`;
const array = [...];  // the string array
const offset = 0x1a2;  // the offset from accessor function

const deobfuscated = code.replace(
    /_0x2b1c\('0x([0-9a-fA-F]+)'\)/g,
    (match, hex) => {
        const index = parseInt(hex, 16) - offset;
        const str = array[index];
        return JSON.stringify(str);  // or '${str}' for template literals
    }
);

console.log(deobfuscated);
```

### Quick String Array Dump

```javascript
// Insert this at the top of the obfuscated code:
(function() {
    const originalArray = _0x5a3f;  // replace with actual array name
    const originalAccessor = _0x2b1c;  // replace with actual function name
    
    // Override the accessor to log
    window._0x2b1c = function(index) {
        const realIndex = parseInt(index, 16) - 0x1a2;
        console.log(`String[${realIndex}]: ${originalArray[realIndex]}`);
        return originalAccessor(index);
    };
})();
```

---

## Control Flow Flattening (CFF)

### Pattern

```javascript
// VULN-like pattern: state machine in a while loop
var _0x3f2a = 0;
while (_0x3f2a < _0x4b1c) {
    switch (_0x3f2a) {
        case 0x0:
            _0x5e2d = 'api/users';
            _0x3f2a = 0x1;
            break;
        case 0x1:
            _0x7f1a = 'GET';
            _0x3f2a = 0x2;
            break;
        case 0x2:
            fetch(_0x5e2d, {method: _0x7f1a});
            _0x3f2a = 0x3;
            break;
        // ... hundreds of cases
    }
}
```

### How to Deobfuscate CFF

**Method 1: Trace execution with console.log**

```javascript
// Insert at the start of the function:
let state = 0;  // initial state
const originalSwitch = _0x3f2a;
const states = {};

// Override to trace
window._0x3f2a = function() {
    // Log current state and variables
    console.log('State:', state, 'Vars:', {_0x5e2d, _0x7f1a, ...});
    return originalSwitch.apply(this, arguments);
};
```

**Method 2: Use a deobfuscator (Synchrony, js-beautify)**

```bash
# Synchrony handles CFF well
synchrony obfuscated.js -o deobfuscated.js
```

**Method 3: Manual state mapping**

```
1. Find the switch variable
2. Find the case statements
3. Map state transitions: case 0 → case 1 → case 2 → case 5 (exit)
4. Reconstruct the logical flow from state transitions
5. Ignore dead states (states that never transition to exit)
```

---

## Constant Obfuscation

### Math Expression Evaluation

```javascript
// Obfuscated: '0x1a + 0x2b' = 65 = 'A'
// Tools:
const expr = '0x1a + 0x2b';
const result = eval(expr);  // 65
const char = String.fromCharCode(result);  // 'A'

// Common patterns:
'0x1a + 0x2b'          // hex addition
'0x1a2b.toString(16)'  // hex string
'String.fromCharCode(65)'  // char code
'atob("QQ==")'         // base64 decode
'btoa("A")'            // base64 encode
'0x41["toString"]("0x10")'  // hex to decimal
```

### Automated Constant Evaluation

```javascript
// Run in Node.js:
function deobfuscateConstants(code) {
    return code.replace(
        /'([^']+)'/g,  // find quoted expressions
        (match, expr) => {
            try {
                const result = eval(expr);
                if (typeof result === 'string') {
                    return JSON.stringify(result);
                }
                return result.toString();
            } catch {
                return match;  // leave if can't evaluate
            }
        }
    );
}

const obfuscated = `var x = '0x1a + 0x2b'; var y = 'atob("QQ==")';`;
console.log(deobfuscateConstants(obfuscated));
// Output: var x = 65; var y = 'A';
```

---

## Runtime Deobfuscation (Chrome DevTools)

### Method 1: Hook Functions

```javascript
// In Console tab, before running the code:

// Hook eval
const originalEval = window.eval;
window.eval = function(code) {
    console.log('[EVAL]', code);
    return originalEval.apply(this, arguments);
};

// Hook setTimeout/setInterval
const originalSetTimeout = window.setTimeout;
window.setTimeout = function(code, delay) {
    if (typeof code === 'string') {
        console.log('[SETTIMEOUT]', code);
    }
    return originalSetTimeout.apply(this, arguments);
};

// Hook Function constructor
const originalFunction = window.Function;
window.Function = function(...args) {
    console.log('[FUNCTION]', args);
    return originalFunction.apply(this, arguments);
};

// Hook document.write
const originalWrite = document.write;
document.write = function(content) {
    console.log('[DOCUMENT.WRITE]', content);
    return originalWrite.apply(this, arguments);
};
```

### Method 2: Breakpoint Debugging

```
1. Open Chrome DevTools (F12)
2. Go to Sources tab
3. Find the obfuscated JS file in the file tree
4. Set a breakpoint on:
   - The first line of the obfuscated function
   - Before eval/Function constructor calls
   - Before document.write/innerHTML assignments
5. Trigger the obfuscated code (click button, load page)
6. Step through (F10 = step over, F11 = step into)
7. Watch variables change in the right panel
8. Copy variable values as they resolve
```

### Method 3: Break on Attribute Modification

```
1. In Elements tab, find the element being modified
2. Right-click → Break on → Subtree modifications
3. Trigger the modification
4. DevTools breaks at the line that modifies the element
5. Call stack shows the obfuscated code path
```

### Method 4: XHR/Fetch Breakpoints

```
1. In Network tab, find the XHR/fetch request
2. Right-click → Break on... (if available)
3. Or: set XHR breakpoint in Sources → XHR Breakpoints → Add
4. Trigger the request
5. Break on the line that makes the XHR
6. Trace back to find the URL construction
```

---

## Anti-Tamper / Anti-Debug Bypass

### Common Anti-Tamper Techniques

```javascript
// 1. Debugger detection
setInterval(() => { debugger; }, 100);
// Bypass: In DevTools, run: setInterval(() => {}, 1000) to replace
// Or: debugger; → never pause (DevTools setting)

// 2. DevTools detection via debugger timing
const start = performance.now();
debugger;
const end = performance.now();
if (end - start > 100) {
    // DevTools is open (debugger caused pause)
}

// 3. Console.log detection
const devtools = { open: false, orientation: null };
const element = new Image();
Object.defineProperty(element, 'id', { get: () => { devtools.open = true; } });
console.log('%c', element);
console.log('%c', element);  // triggers second log
if (devtools.open) {
    // Code is modified or execution blocked
}

// 4. Source map check
// Detects if devtools is open by checking for .map file loading

// 5. Timing attacks
const before = Date.now();
// ... code ...
const after = Date.now();
if (after - before > expected) {
    // Debugger stepped through, too slow
}
```

### Anti-Debug Bypass Scripts

```javascript
// Paste in Console:

// 1. Disable debugger
(function() {
    const interval = setInterval(() => {}, 1000);
    const originalDebugger = console.debug;
    console.debug = function() {};
    debugger = function() {};
})();

// 2. Override performance.now for timing attacks
const originalNow = performance.now;
performance.now = function() {
    return originalNow.call(performance);
};

// 3. Disable setInterval-based debugger
window.setInterval = function(callback, delay) {
    if (delay < 1000) {
        return window.setInterval(() => {}, 1000);  // replace fast intervals
    }
    return window.setInterval(callback, delay);
};
```

---

## Packed JS Detection & Unpacking

### Detecting Packers

```bash
# Check for eval/Function constructor with encoded data
grep -rn "eval(\|new Function\|setTimeout.*eval\|setInterval.*eval" --include="*.js" | head -20

# Check for base64 encoded data
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' file.js | head -5

# Check for large blob of data
wc -c file.js  # if > 100KB, likely packed

# Check for hex/unicode heavy content
grep -oE '\\x[0-9a-fA-F]{2}' file.js | wc -l  # high count = obfuscated

# Check for array of strings
grep -n "var _0x" file.js | head -20  # many _0x variables = obfuscated
```

### Unpacking Strategy

```javascript
// For eval-wrapped code:
// 1. Replace eval with console.log to see what's being evaluated
eval = console.log;  // in browser console
// 2. Trigger the code (load page, click button)
// 3. The "eval'd" code is now printed in console
// 4. Copy and analyze that code

// For Function constructor:
// 1. Hook Function constructor
const OriginalFunction = window.Function;
window.Function = function(...args) {
    console.log('Function constructor args:', args);
    const fn = OriginalFunction.apply(this, args);
    console.log('Function body:', fn.toString());
    return fn;
};

// For packed code with array:
// 1. Find the unpack function
// 2. Call it with the array to get the real code
const unpacked = unpacker(_0x5a3f, _0x2b1c);
console.log(unpacked);
```

---

## AST Analysis (Advanced)

### Using Babel Parser

```bash
# Install
npm3 install @babel/parser @babel/traverse @babel/generator

# Parse JS to AST
node -e "
const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const generate = require('@babel/generator').default;

const code = fs.readFileSync('obfuscated.js', 'utf8');
const ast = parser.parse(code);

traverse(ast, {
    CallExpression(path) {
        // Find all function calls
        if (path.node.callee.name === '_0x5a3f') {
            // This is a string array access
            console.log('String access:', path.node.arguments[0].value);
        }
    },
    MemberExpression(path) {
        // Find property accesses like _0x5a3f[0]
        console.log('Member:', path.toString());
    }
});
"
```

### Using Esprima

```bash
# Install
npm3 install esprima

# Parse
node -e "
const esprima = require('esprima');
const code = fs.readFileSync('obfuscated.js', 'utf8');
const ast = esprima.parseScript(code, { loc: true, range: true });

// Find all string literals
function findStrings(node) {
    if (node.type === 'Literal' && typeof node.value === 'string') {
        console.log(\`Line \${node.loc.start.line}: \${node.value}\`);
    }
    for (let key in node) {
        if (node[key] && typeof node[key] === 'object') {
            if (Array.isArray(node[key])) {
                node[key].forEach(findStrings);
            } else {
                findStrings(node[key]);
            }
        }
    }
}
findStrings(ast);
"
```

---

## Obfuscator.io Specific Deobfuscation

### Common Patterns

```javascript
// String array with hex keys
var _0x5a3f = ['api/users', 'Authorization', 'Bearer token'];
var _0x2b1c = function(_0x5a3f, _0x2b1c) {
    _0x5a3f = _0x5a3f - 0x1a2;
    var _0x2b1c = _0x5a3f[_0x2b1c];
    return _0x2b1c;
};

// Rotating string array
function _0x5a3f(_0x2b1c) {
    var _0x4d5e = ['a', 'b', 'c'];
    return _0x4d5e[_0x2b1c];
}

// Object property obfuscation
var _0x7f3a = {};
_0x7f3a['\x61\x70\x69\x2f\x75\x73\x65\x72\x73'] = '/api/users';  // hex encoded key
_0x7f3a['\x41\x75\x74\x68\x6f\x72\x69\x7a\x61\x74\x69\x6f\x6e'] = 'Authorization';
```

### Deobfuscation Script

```javascript
// deobfuscator.js
const fs = require('fs');
const code = fs.readFileSync('obfuscated.js', 'utf8');

// 1. Replace _0xXXXX accessor calls
const arrayMatch = code.match(/var\s+(_0x\w+)\s*=\s*\[([^\]]+)\]/);
if (arrayMatch) {
    const arrayName = arrayMatch[1];
    const arrayContent = eval('[' + arrayMatch[2] + ']');
    
    const accessorMatch = code.match(new RegExp(
        `var\s+(_0x\\w+)\s*=\\s*function\\(_0x\\w+,\\s*_0x\\w+\\)\\s*\\{[^}]*_0x\\w+\\s*=\\s*_0x\\w+\\s*-\\s*(0x[0-9a-fA-F]+)`
    ));
    
    if (accessorMatch) {
        const accessorName = accessorMatch[1];
        const offset = parseInt(accessorMatch[2]);
        
        console.log(`Array: ${arrayName}`);
        console.log(`Accessor: ${accessorName}`);
        console.log(`Offset: ${offset}`);
        console.log(`Content: ${JSON.stringify(arrayContent)}`);
        
        // Replace calls
        const deobfuscated = code.replace(
            new RegExp(`${accessorName}\\(('0x[0-9a-fA-F]+')\\)`, 'g'),
            (match, hex) => {
                const index = parseInt(hex, 16) - offset;
                const value = arrayContent[index];
                return typeof value === 'string' ? JSON.stringify(value) : value;
            }
        );
        
        fs.writeFileSync('deobfuscated-step1.js', deobfuscated);
        console.log('Step 1 complete: deobfuscated-step1.js');
    }
}
```

---

## Deobfuscation Workflow

### Step-by-Step Process

```
STEP 1: IDENTIFY THE OBFUSCATOR
├── Look for characteristic patterns
├── Check footer comments: "Obfuscated with obfuscator.io"
├── Try de4js with different obfuscator types
└── Identify: obfuscator.io, javascript-obfuscator, custom, packer

STEP 2: EXTRACT STRINGS
├── Find the string array
├── Find the accessor function
├── Calculate the offset
├── Dump all strings
└── This gives you 70% of the readable content

STEP 3: REMOVE DEAD CODE
├── Identify code that never executes
├── Remove infinite loops with no exit
├── Remove try/catch blocks that swallow errors
└── Remove code after unconditional return

STEP 4: SIMPLIFY CONTROL FLOW
├── Flattened switch → linear flow
├── Use Synchrony or manual mapping
├── Rename variables to meaningful names
└── Reorder code to logical sequence

STEP 5: EVALUATE CONSTANTS
├── Math expressions → values
├── Hex strings → readable strings
├── Base64 → decoded strings
└── Unicode escapes → actual characters

STEP 6: HOOK FOR REMAINING MYSTERIES
├── Runtime-generated code?
├── eval/Function at runtime?
├── WebAssembly?
└── Use Chrome DevTools to trace execution
```

---

## Obfuscation Strength vs. Your Time

| Obfuscation Level | Time to Deobfuscate | Approach |
|-------------------|---------------------|----------|
| js-beautify only | 5 minutes | Run js-beautify, review |
| String array + renaming | 15 minutes | Extract strings, replace calls |
| Control flow flattening | 30-60 minutes | Use Synchrony or manual trace |
| Self-defending + debugger traps | 1-2 hours | Bypass anti-debug, then deobfuscate |
| VM-based (custom bytecode) | Days+ | Reverse the VM first, or use runtime tracing |
| WebAssembly + JS glue | Variable | Analyze WASM separately |

**Rule of thumb:** If it takes more than 2 hours to deobfuscate one file, move on. You can often understand the logic from:
1. Network requests (what URLs does it call?)
2. String extraction (what strings are in the array?)
3. XHR/fetch hooks (what data does it send?)

---

## Practical Deobfuscation Example

### Before (Obfuscated)

```javascript
var _0x3f2a=['api/v2/users','POST','Authorization','Bearer eyJhbG...','https://target.com'];var _0x5e2d=function(_0x3f2a,_0x5e2d){_0x3f2a=_0x3f2a-0x1a2;var _0x5e2d=_0x3f2a[_0x5e2d];return _0x5e2d;};(function(){var _0x7f1a=_0x5e2d('0x1a2');var _0x9b4c=_0x5e2d('0x1a3');var _0x2d5e=_0x5e2d('0x1a4');var _0x8f3a=_0x5e2d('0x1a5');fetch(_0x7f1a,{method:_0x9b4c,headers:{[_0x2d5e]:_0x8f3a}})})();
```

### After (Deobfuscated)

```javascript
// Strings extracted:
// _0x5e2d('0x1a2') = 'api/v2/users'  (index = 0x1a2 - 0x1a2 = 0)
// _0x5e2d('0x1a3') = 'POST'          (index = 0x1a3 - 0x1a2 = 1)
// _0x5e2d('0x1a4') = 'Authorization' (index = 0x1a4 - 0x1a2 = 2)
// _0x5e2d('0x1a5') = 'Bearer eyJhbG...' (index = 0x1a5 - 0x1a2 = 3)

// Deobfuscated code:
(function() {
    var endpoint = 'api/v2/users';
    var method = 'POST';
    var headerKey = 'Authorization';
    var headerValue = 'Bearer eyJhbG...';
    
    fetch(endpoint, {
        method: method,
        headers: {
            [headerKey]: headerValue
        }
    });
})();
```

---

## Deobfuscation Tools Summary

| Tool | Best For | Install |
|------|----------|---------|
| de4js | Online deobfuscation | Web UI |
| js-beautify | Formatting only | `npm3 install js-beautify` |
| Synchrony | CFF + string arrays | `git clone relative/synchrony` |
| JSNice | Variable renaming | Web UI |
| jsnice.org | Statistical renaming | Web UI |
| Retire.js | Vulnerable library detection | `npm3 install retire` |
| Chrome DevTools | Runtime deobfuscation | Built into Chrome |
| Burp JS Miner | JS analysis in Burp | Burp extension |

---

## Quick Deobfuscation Checklist

```
[ ] Run js-beautify to get readable formatting
[ ] Try de4js with obfuscator.io selected
[ ] Try JSNice for variable renaming
[ ] Find and dump the string array
[ ] Replace all _0xXXXX() calls with actual strings
[ ] Look for eval/Function/console.log with encoded data
[ ] Check for control flow flattening (big while loop)
[ ] Check for debugger traps (setInterval with debugger)
[ ] Hook functions in Chrome DevTools console
[ ] Set breakpoints before eval/Function calls
[ ] Step through to understand runtime behavior
[ ] Extract API endpoints from deobfuscated strings
[ ] Extract secrets from deobfuscated strings
[ ] Document findings for security analysis
```

---

## When NOT to Deobfuscate

- Third-party library (Google Analytics, jQuery) — skip, not interesting
- Minified but not obfuscated — js-beautify is enough
- WASM-heavy app — analyze WASM instead
- Time-consuming (>2 hours) with no clear path forward
- Already found the interesting endpoints via other methods

Deobfuscation is a means to an end. The end is finding bugs.

---

## Advanced Obfuscation Patterns and Countermeasures

### Advanced String Encoding Schemes

#### Base64 with Rotation

```javascript
// Pattern: Base64 encoded strings with character rotation
var _0x5a3f = [];
function _0x2b1c(str) {
    // Decode: rotate chars then base64 decode
    var rotated = '';
    for (var i = 0; i < str.length; i++) {
        rotated += String.fromCharCode(str.charCodeAt(i) - 3);
    }
    return atob(rotated);
}

// Decoder script:
function decodeRotatedBase64(encoded) {
    let rotated = '';
    for (let i = 0; i < encoded.length; i++) {
        rotated += String.fromCharCode(encoded.charCodeAt(i) + 3);
    }
    return atob(rotated);
}

// Test:
console.log(decodeRotatedBase64('Sdvvrf@edwxq')); // Decodes with +3 rotation
```

#### XOR Encoding

```javascript
// Pattern: XOR-encoded strings
var _0x5a3f = [0x1a, 0x2b, 0x3c, 0x4d];  // XOR keys
function _0x2b1c(str, key) {
    var result = '';
    for (var i = 0; i < str.length; i++) {
        result += String.fromCharCode(str.charCodeAt(i) ^ key[i % key.length]);
    }
    return result;
}

// Decoder:
function xorDecode(encoded, key) {
    let result = '';
    for (let i = 0; i < encoded.length; i++) {
        result += String.fromCharCode(encoded.charCodeAt(i) ^ key[i % key.length]);
    }
    return result;
}
```

#### RC4 Decryption

```javascript
// Pattern: RC4 encrypted strings
function rc4(key, data) {
    var S = [], j = 0, x, result = '';
    for (var i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
        x = S[i]; S[i] = S[j]; S[j] = x;
    }
    i = j = 0;
    for (var k = 0; k < data.length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        x = S[i]; S[i] = S[j]; S[j] = x;
        result += String.fromCharCode(data.charCodeAt(k) ^ S[(S[i] + S[j]) % 256]);
    }
    return result;
}

// Usage:
var encrypted = [0x5a, 0x3f, 0x2b, 0x1c]; // encrypted bytes
var key = 'secret_key';
var decrypted = rc4(key, encrypted);
```

### Custom Packers and Loaders

#### Webpack Bundle Analysis

```javascript
// Webpack bundles use specific patterns:
// - webpackBootstrap (webpack 4)
// - __webpack_require__ function
// - Module IDs as numbers or strings

// Deobfuscating webpack:
// 1. Find webpackBootstrap / __webpack_require__
// 2. Identify module cache: webpack_module_cache
// 3. Map module IDs to actual code
// 4. Use webpack-deobfuscator tool

// webpack-deobfuscator:
// npm3 install webpack-deobfuscator
// node webpack-deobfuscator.js -i bundle.js -o deobfuscated.js
```

#### Browserify Analysis

```javascript
// Browserify pattern:
(function e(t,n,r){...})({1:[function(require,module,exports){
    // Module 1 code here
    module.exports = ...
}]}, {}, [1]);

// Deobfuscating browserify:
// 1. The first argument is the module cache
// 2. Keys are module IDs (numbers or paths)
// 3. Values are functions(require, module, exports)
// 4. Third argument is entry modules

// Extract modules:
var cache = { /* first argument */ };
for (var id in cache) {
    console.log("Module " + id + ":");
    console.log(cache[id].toString().substring(0, 500));
}
```

#### Rollup Analysis

```javascript
// Rollup bundles:
var foo = 'export function bar() { ... }';
var bar = 'export default class Baz { ... }';

// Rollup uses variable assignments for exports
// Look for:
// - var/let/const followed by export assignments
// - __export calls with destructuring
// - Object.defineProperty(exports, "__esModule", {value: true})

// Deobfuscate by:
// 1. Finding exports object
// 2. Extracting assigned functions/classes
// 3. Reconstructing module structure
```

---

## Anti-Debug and Anti-Tamper Techniques

### Advanced Anti-Debug

```javascript
// 1. Timing-based detection
const start = performance.now();
debugger;  // If DevTools open, this causes a pause
const elapsed = performance.now() - start;
if (elapsed > 100) {
    // DevTools is open (pause was longer than expected)
    // Break the code / modify behavior / exit
}

// 2. Console.log fingerprinting
const element = new Image();
Object.defineProperty(element, 'id', {
    get: function() {
        // If DevTools is open, console.log on elements triggers this
        devtools.open = true;
    }
});
console.log('%c', element);  // Triggers getter if DevTools open

// 3. Debugger statement flooding
setInterval(() => { debugger; }, 50);
// Even with "Never pause here" enabled, creates massive slowdown

// 4. Function toString override
Function.prototype.toString = function() {
    if (devtools.open) return 'function() { /* obfuscated */ }';
    return originalToString.call(this);
};

// 5. Call stack inspection
try {
    throw new Error();
} catch (e) {
    const stack = e.stack;
    if (stack.includes('devtools') || stack.includes('chrome://')) {
        // DevTools detected via stack trace
    }
}

// 6. Window size check (DevTools open changes window size)
setInterval(() => {
    if (window.outerWidth - window.innerWidth > 160 ||
        window.outerHeight - window.innerHeight > 160) {
        // DevTools likely open
    }
}, 1000);
```

### Anti-Tamper Countermeasures

```javascript
// Bypass script for browser console:

// 1. Disable all debugger statements
const scripts = document.querySelectorAll('script');
scripts.forEach(script => {
    const originalText = script.textContent;
    script.textContent = originalText.replace(/debugger;/g, '');
});

// 2. Override setInterval to skip debugger
let debuggerCount = 0;
const originalSetInterval = window.setInterval;
window.setInterval = function(callback, delay, ...args) {
    const wrappedCallback = function() {
        debuggerCount++;
        if (debuggerCount > 10) {
            // Replace with no-op after many debugger hits
            return;
        }
        return callback.apply(this, args);
    };
    return originalSetInterval.call(this, wrappedCallback, delay);
};

// 3. Override performance.now for timing attacks
const originalNow = performance.now;
const originalDateNow = Date.now;
let fakeTime = 0;
performance.now = function() { return fakeTime; };
Date.now = function() { return fakeTime; };

// 4. Disable console.log in production
console.log = function() {};
console.debug = function() {};
console.info = function() {};
console.warn = function() {};
```

### Self-Defending Code

```javascript
// Self-defending code detects modification:
(function() {
    'use strict';
    
    // Hash of original code
    const originalHash = 'a1b2c3d4e5f6...';
    
    // Calculate current hash
    const currentCode = document.currentScript.textContent;
    const currentHash = simpleHash(currentCode);
    
    if (currentHash !== originalHash) {
        // Code was modified
        // Could: exit, modify behavior, phone home
        window.stop();
        document.body.innerHTML = 'Code integrity check failed';
    }
    
    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;  // Convert to 32bit integer
        }
        return hash.toString(16);
    }
})();
```

---

## Virtual Machine-Based Obfuscation

### Detecting VM Obfuscation

```javascript
// VM-based obfuscation (most sophisticated):
// - Code compiled to custom bytecode
// - Interpreter loop executes bytecode
// - Very hard to statically analyze

// Detection patterns:
// 1. Large switch statement with many cases
// 2. Byte array as "instructions"
// 3. Stack-based operations (push/pop)
// 4. Register simulation (variables named r0, r1, r2...)

// Example pattern:
const bytecode = [0x01, 0x02, 0x03, 0x04, ...];  // Instructions
const stack = [];
const registers = {};

function interpret(opcode) {
    switch(opcode) {
        case 0x01:  // PUSH
            stack.push(nextByte());
            break;
        case 0x02:  // POP
            stack.pop();
            break;
        case 0x03:  // ADD
            registers['r0'] = stack.pop() + stack.pop();
            break;
        // ... hundreds more opcodes
    }
}
```

### VM Deobfuscation Strategy

```
For VM-based obfuscation:

1. Identify the interpreter loop
   - Find the main switch/dispatch
   - Identify opcode handling

2. Map the bytecode
   - Extract the byte array
   - Identify each opcode's function
   - Document the instruction set

3. Trace execution
   - Set breakpoint in interpreter
   - Step through each opcode
   - Record stack/register state at each step

4. Build a disassembler
   - Map opcodes to readable operations
   - Convert bytecode to pseudo-code

5. Or: use dynamic analysis
   - Hook the VM's execution
   - Log every instruction as it executes
   - Reconstruct logic from execution trace
```

---

## WAF Evasion Through Obfuscation

### Encoding Payloads for WAF Bypass

```javascript
// When analyzing obfuscated code that generates attack payloads:

// 1. Unicode encoding
<script>alert(1)</script>
→ \u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e

// 2. HTML entity encoding
→ &lt;script&gt;alert(1)&lt;/script&gt;

// 3. Hex encoding
→ \x3c\x73\x63\x72\x69\x70\x74\x3e\x61\x6c\x65\x72\x74\x28\x31\x29\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e

// 4. Octal encoding
→ \74\151\156\151\164\171\163\143\162\151\160\164\76\141\154\145\162\164\50\61\51\74\57\151\156\151\164\171\163\143\162\151\160\164\76

// 5. Mixed encoding
→ \x3c\x73\x63&#x72;&#x69;&#x70;&#x74;>alert(1)</script>

// Decoding tool:
function decodePayload(encoded) {
    return encoded
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/&#([0-9]+);/g, (_, dec) => String.fromCharCode(parseInt(dec)))
        .replace(/\\([0-7]{1,3})/g, (_, oct) => String.fromCharCode(parseInt(oct, 8)));
}
```

---

## Malware Analysis in JS

### Detecting Malicious JavaScript

```bash
# Indicators of malicious JS:
grep -rn "eval(" --include="*.js" | head -20
grep -rn "document\.write" --include="*.js" | head -20
grep -rn "setTimeout.*eval" --include="*.js" | head -20
grep -rn "new Function" --include="*.js" | head -20
grep -rn "\.fromCharCode" --include="*.js" | head -20
grep -rn "\\x\|\\u" --include="*.js" | head -20

# Suspicious external connections
grep -oE 'https?://[^"'\''>\s]+' malicious.js | sort -u

# Suspicious patterns
grep -rn "crypto\.subtle\|WebAssembly\|atob\|btoa" --include="*.js"
grep -rn "XMLHttpRequest.*send\|fetch\(" --include="*.js"
grep -rn "navigator\.clipboard\|navigator\.geolocation" --include="*.js"
```

### JS Malware Deobfuscation Workflow

```
1. Initial analysis:
   - Check file size (malware often larger)
   - Check entropy (high entropy = packed/encrypted)
   - Check for eval/Function at top level

2. String extraction:
   - Find all string arrays
   - Decode encoded strings
   - Identify URLs, C2 servers, payloads

3. Control flow analysis:
   - Identify main execution path
   - Find conditional branches (what triggers what?)
   - Look for time-based triggers

4. Network analysis:
   - Extract all URLs
   - Identify C2 communication
   - Check for data exfiltration patterns

5. Payload extraction:
   - Find embedded payloads (shellcode, secondary malware)
   - Decode/decompress if necessary
   - Identify persistence mechanisms
```

---

## Browser Extension Analysis

### Chrome Extension Security

```bash
# Extension structure:
# manifest.json - configuration
# background.js - service worker
# content.js - runs in web pages
# popup.html/js - extension UI

# Key things to check in manifest.json:
# - permissions: what can extension access?
# - host_permissions: which sites?
# - content_scripts: injected into which pages?
# - web_accessible_resources: exposed to web pages

# Content script vulnerabilities:
grep -rn "innerHTML\|outerHTML\|document\.write" content.js
grep -rn "postMessage" content.js  # Can send messages to page
grep -rn "chrome\.tabs\.executeScript" background.js  # Can inject JS into pages
```

### Extension XSS → Chrome API Abuse

```javascript
// If content script has XSS AND extension has sensitive permissions:
// Attacker can abuse Chrome extension APIs

// Example: Extension with "tabs" permission
chrome.tabs.query({}, function(tabs) {
    // Can read all open tabs
    // If content script has XSS → attacker runs this code
    tabs.forEach(tab => {
        // Steal all form data from all tabs
        chrome.tabs.sendMessage(tab.id, {action: 'stealForms'});
    });
});
```

---

## Final Deobfuscation Rule

> **Obfuscation is a speed bump, not a wall. Every obfuscation technique has a counter. The goal is not perfect deobfuscation — it's understanding what the code does. If you can answer "what does this JS do?" you've won, even if the code still looks messy.**

Deobfuscation priorities:
1. Extract all strings (gives you 70% of the answer)
2. Identify API endpoints and parameters
3. Find secrets and keys
4. Understand the authentication flow
5. Map the attack surface

Don't spend 8 hours perfectly deobfuscating one file. Extract what you need and move on.
