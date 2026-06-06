---
name: deobfuscation-guide
description: JavaScript deobfuscation techniques for bug bounty hunters. Covers unpacking, beautifying, debugging, and extracting hidden logic, endpoints, and secrets from obfuscated client-side code. Use when analyzing heavily obfuscated JS, packed scripts, or reversing prototype pollution gadgets. Chinese trigger: 反混淆、deobfuscation、JS解混淆、obfuscation bypass、混淆代码分析
---

# Deobfuscation Guide

JavaScript deobfuscation techniques and strategies.

---

## DEOBFUSCATION PHILOSOPHY

```
DEOBFUSCATION LIFECYCLE:
1. IDENTIFY — Recognize what obfuscation technique is used
2. ANALYZE — Understand the obfuscation pattern
3. AUTOMATE — Use tools to partially deobfuscate
4. MANUAL — Fill gaps with manual analysis
5. SIMPLIFY — Reduce to readable logic
6. HUNT — Find the security-relevant code
```

### Why Deobfuscate?

```
What you find after deobfuscation:
- Hidden API endpoints (obfuscated to hide from crawlers)
- Encrypted secrets (API keys, credentials)
- Business logic (coupon validation, price calculation)
- Authorization checks (client-side, bypassable)
- Sensitive data processing (PII handling)
- Vulnerabilities (XSS sinks, SSTI, prototype pollution)
- Hardcoded credentials
- Internal URLs/hostnames
- Debug endpoints
- Admin-only logic hidden in obfuscated code
```

---

## OBFUSCATION TECHNIQUES IDENTIFICATION

### Common Obfuscation Methods

| Technique | Signs | Difficulty |
|-----------|-------|------------|
| Minification | Long lines, short variable names | Easy |
| String array obfuscation | _0x array, string index lookups | Medium |
| Hex/Unicode encoding | \xNN, \uNNNN patterns | Medium |
| eval() wrapping | eval(decode(str)) | Medium |
| Control flow flattening | Switch statements, state variables | Hard |
| Dead code injection | Unreachable code, confusing paths | Hard |
| Domain locking | Checks document.domain, self == top | Easy |
| Constant obfuscation | Encode(_0x[0]) + Encode(_0x[1]) | Easy |
| Object property obfuscation | _0x['prop'] instead of prop | Medium |
| Function name mangling | _0xabcd(), _0x1234() | Easy |
| Self-defending code | Debugger statements, anti-tamper | Hard |

### Identifying Obfuscation Type

```bash
# 1. Check file size
wc -c obfuscated.js
# If >100KB single file = likely obfuscated

# 2. Check for eval
grep -c 'eval(' obfuscated.js
grep -c 'Function(' obfuscated.js

# 3. Check for hex strings
grep -oE '\\x[0-9a-fA-F]{2}' obfuscated.js | wc -l

# 4. Check for _0x patterns
grep -oE '_0x[a-zA-Z0-9]+' obfuscated.js | sort -u | wc -l

# 5. Check for long lines
awk 'length > 5000 {print NR ": " length}' obfuscated.js

# 6. Check for switch-case obfuscation
grep -c 'switch' obfuscated.js

# 7. Check for base64
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' obfuscated.js | wc -l

# 8. Check for anti-debugging
grep -in 'debugger' obfuscated.js
grep -in 'devtools' obfuscated.js
grep -in 'console\..*detect' obfuscated.js
```

---

## MANUAL DEOBFUSCATION

### Step 1: Pretty Print

```javascript
// Before (minified):
function a(b,c){var d=b[0];return d===c[0]?a(b,c):b<c?d:c}

// After (beautified):
function compareValues(array1, array2) {
  var first = array1[0];
  if (first === array2[0]) {
    return compareValues(array1, array2);
  }
  return array1 < array2 ? first : array2[0];
}
```

```bash
# Use js-beautify
js-beautify obfuscated.js > readable.js

# Use prettier
prettier --parser babel obfuscated.js > readable.js
```

### Step 2: Rename Variables

```javascript
// Before:
function _0x1a2b(_0x3c4d, _0x5e6f) {
  var _0x7g8h = _0x3c4d[0];
  if (_0x7g8h === _0x5e6f[0]) return _0x1a2b(_0x3c4d, _0x5e6f);
  return _0x3c4d < _0x5e6f ? _0x7g8h : _0x5e6f[0];
}

// After manual rename:
function compareValues(arr1, arr2) {
  var firstVal = arr1[0];
  if (firstVal === arr2[0]) return compareValues(arr1, arr2);
  return arr1 < arr2 ? firstVal : arr2[0];
}
```

### Step 3: Deobfuscate String Arrays

```javascript
// Common pattern: string array + index lookups
var _0xabcd = ['console', 'log', 'alert', 'innerHTML', 'eval', 'document', 'cookie', 'fetch'];

function _0x1234(_0x5678) {
  return _0xabcd[_0x5678];
}

// Usage:
_0x1234(3);  // Returns: 'innerHTML'
_0x1234(6);  // Returns: 'cookie'

// Deobfuscation approach:
// 1. Find all _0x[var] pattern usages
// 2. Track what indices are used
// 3. Map indices to actual strings
```

```python
# Python script to deobfuscate string arrays
import re

with open('obfuscated.js') as f:
    code = f.read()

# Find string arrays
arrays = re.findall(r'var ([_0-9a-zA-Z]+) = \[(.*?)\];', code, re.DOTALL)

for name, content in arrays:
    # Parse array contents
    elements = re.findall(r"'([^']*)'", content)
    print(f"\nArray: {name}")
    for i, elem in enumerate(elements):
        print(f"  [{i}] = '{elem}'")

# Substitute array lookups
for name, _ in arrays:
    pattern = rf'{name}\[(\d+)\]'
    print(f"\nPattern: {pattern}")
```

### Step 4: Deobfuscate eval() Wrappers

```javascript
// Pattern 1: eval with encoded string
eval(atob('Y29uc29sZS5sb2c='));  // console.log

// Pattern 2: eval with hex
eval('\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67');  // console.log

// Pattern 3: eval with function
(function(_0x1a2b){eval(atob(_0x1a2b))})('Y29uc29sZS5sb2c=');

// Deobfuscation approach:
// 1. Change eval to console.log to see what was being executed
// 2. Or: run in Node.js with console.log interception

// Manual conversion:
echo 'Y29uc29sZS5sb2c=' | base64 -d
# Output: console.log
```

### Step 5: Control Flow Flattening

```javascript
// Before (flattened):
var _0xstate = 0;
var _0xinput = [1, 2, 3, 4, 5];
var _0xoutput = [];

function _0xprocess() {
  switch(_0xstate) {
    case 0:
      if (_0xinput.length > 0) {
        _0xoutput.push(_0xinput.shift());
        _0xstate = 1;
      } else {
        _0xstate = 3;
      }
      break;
    case 1:
      _0xstate = 2;
      break;
    case 2:
      _0xstate = 0;
      break;
    case 3:
      return _0xoutput;
  }
  _0xprocess();
}

// After (simplified):
function process(input) {
  var output = [];
  while (input.length > 0) {
    output.push(input.shift());
  }
  return output;
}
```

**Deobfuscation strategy for control flow:**
1. Identify state variable
2. Map each state to its purpose
3. Reconstruct the actual flow
4. Replace switch with normal control structures

### Step 6: Dead Code Removal

```javascript
// Dead code pattern 1: unreachable if
if (false) {
  // Never executes, remove
}

// Dead code pattern 2: misleading variables
var _0x1 = complexCalculation();  // Result never used
var _0x2 = something();            // Nothing done with it

// Dead code pattern 3: infinite loops with break after first iter
while (true) {
  doSomething();
  break;
}
// Replace with: doSomething();

// Dead code pattern 4: try-catch with empty catch
try {
  realLogic();
} catch (e) {
  // Silent catch
}

// Automated dead code removal:
// Use ESLint with --fix to clean up
eslint --fix readable.js
```

---

## AUTOMATED DEOBFUSCATION TOOLS

### Online Deobfuscators

```
JS Nice (online):
https://www.jsnice.org/
- Renames variables to meaningful names
- Infers types
- Adds indentation
- Good for minified code

Unminify (online):
https://unminify.com/
- Basic beautification

Prettier (online):
https://prettier.io/playground/
- Formatting only
```

### Offline Deobfuscation Tools

```bash
# js-beautify
npm install -g js-beautify
js-beautify obfuscated.js > beautified.js

# prettier
npm install -g prettier
prettier --parser babel obfuscated.js > prettified.js

# deobfuscate.io (CLI)
npm install -g de4js
de4js

# js-beautify with custom options
js-beautify -s 2 -c -p obfuscated.js > beautified.js

# Babel with preset-env (transpiles modern JS)
npx babel obfuscated.js -o babel-output.js

# swc (fast JS compiler with deobfuscation)
npx swc obfuscated.js -o swc-output.js
```

### Specialized Deobfuscation Tools

```bash
# JStillery - JavaScript deobfuscator
npm install -g jstillery
jstillery obfuscated.js > deobfuscated.js

# js-beautify
npm install -g js-beautify
js-beautify -s 2 -t obfuscated.js

# de4js (deobfuscate multiple engines)
npm install -g de4js
de4js obfuscated.js

# Ast-grep (structural search/replace)
npm install -g @ast-grep/cli
ast-grep scan --pattern '$_ == $$' obfuscated.js
```

---

## SPECIFIC OBFUSCATION PATTERNS

### String Array Obfuscation

```javascript
// Obfuscated:
var _0x1a2b=['api','users','profile','admin','/v1/','/v2/','key','secret'];
var _0x3c4d=function(_0x5e6f,_0x7g8h){return _0x1a2b[_0x5e6f-0x5a];};
var url=_0x3c4d(0x5e)+_0x3c4d(0x5f)+_0x3c4d(0x61);

// Manual deobfuscation:
// _0x3c4d(0x5e) = _0x1a2b[4] = '/v1/'
// _0x3c4d(0x5f) = _0x1a2b[5] = '/v2/'
// _0x3c4d(0x61) = _0x1a2b[7] = 'secret'

// Result: url = '/v1//v2/secret'
// Or more likely: '/api/users/admin/v2/secret'

// Quick script:
python3 -c "
arr = ['api','users','profile','admin','/v1/','/v2/','key','secret']
def get(i): return arr[i - 0x5a]
print(get(0x5e) + get(0x5f) + get(0x61))
"
```

### Hex/Unicode String Encoding

```javascript
// Hex encoding
'\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67'
// Decoded: console.log

// Convert hex to string
python -c "print(''.join(chr(int(x, 16)) for x in '63 6f 6e 73 6f 6c 65'.split()))"
# Or:
echo -e "\x63\x6f\x6e\x73\x6f\x6c\x65"
# Output: console

// Unicode encoding
'\u0063\u006f\u006e\u0073\u006f\u006c\u0065'
// Decoded: console
```

### Constant Obfuscation

```javascript
// Arithmetic obfuscation
var _0x1 = 10 + 5;           // 15
var _0x2 = 0x1a;             // 26 (hex)
var _0x3 = 0b1111;           // 15 (binary)
var _0x4 = 0o17;             // 15 (octal)

// String concatenation obfuscation
var _0x7 = 'con' + 'sole';  // console
var _0x8 = 'co' + 'nso' + 'le';  // console
var _0x9 = 'c' + 'o' + 'n' + 's' + 'o' + 'l' + 'e';  // console

// Conditional expression obfuscation
var _0xa = true ? 'console' : 'window';  // console
var _0xb = 10 > 5 ? 'admin' : 'user';    // admin
```

### VM-Based Obfuscation (Obfuscator.io)

```javascript
// VM-based obfuscation creates a virtual machine
// with custom opcode handling

// Example: obfuscator.io output pattern
var _0x4cbd = ['\x63\x6f\x6e\x73\x6f\x6c\x65', ...];
var _0x31c2 = function(_0x442b, _0x12cf) {
  _0x442b = _0x442b - 0x0;
  var _0x2a7e = _0x4cbd[_0x442b];
  return _0x2a7e;
};

// VM pattern:
while (true) {
  switch (_0xopcodes[_0xpc++]) {
    case 0: // LOAD_STRING
      _0xstack.push(_0x4cbd[_0xarg]);
      break;
    case 1: // LOAD_VAR
      _0xstack.push(_0xscope[_0xarg]);
      break;
    case 2: // CALL
      _0fn = _0xstack.pop();
      // ...execute function
      break;
    // ... many more opcodes
  }
}

// Deobfuscation approach:
// 1. Identify opcode switch
// 2. Map each opcode to its operation
// 3. Replace switch with direct function calls
// 4. Execute decoded logic
```

---

## AUTOMATED DEOBFUSCATION WORKFLOW

### Complete Deobfuscation Pipeline

```bash
#!/bin/bash
# deobfuscate.sh - Full deobfuscation pipeline

INPUT=$1
OUTPUT="deobfuscated.js"

echo "[*] Step 1: Initial beautify"
js-beautify -s 2 $INPUT > step1-beautified.js

echo "[*] Step 2: Detect obfuscation type"
grep -c 'eval(' step1-beautified.js
grep -c '_0x' step1-beautified.js
grep -c '\\x' step1-beautified.js

echo "[*] Step 3: Remove debugger statements"
sed 's/debugger;//g' step1-beautified.js > step2-no-debug.js

echo "[*] Step 4: Replace anti-tamper checks"
sed 's/if (typeof window !== "undefined")/\/\/ removed: window check/g' step2-no-debug.js > step3-clean.js

echo "[*] Step 5: Extract string arrays"
python3 extract-arrays.py step3-clean.js > extracted-strings.txt

echo "[*] Step 6: Replace array lookups"
python3 replace-arrays.py step3-clean.js > step4-deobfuscated.js

echo "[*] Step 7: Remove dead code"
eslint --fix step4-deobfuscated.js

echo "[+] Deobfuscated: $OUTPUT"
```

### String Array Deobfuscation Script

```python
#!/usr/bin/env python3
"""deobfuscate_arrays.py - Extract and replace string array obfuscation"""
import re
import sys

class StringArrayDeobfuscator:
    def __init__(self):
        self.arrays = {}
        self.functions = {}

    def extract_arrays(self, code):
        """Find and parse string arrays"""
        pattern = r'var ([_0-9a-zA-Z]+)\s*=\s*\[(.*?)\];'
        matches = re.findall(pattern, code, re.DOTALL)

        for name, content in matches:
            strings = re.findall(r"'([^']*)'", content)
            if strings:
                self.arrays[name] = strings

    def deobfuscate(self, code):
        """Replace array lookups with actual strings"""
        for name, strings in self.arrays.items():
            for idx, string in enumerate(strings):
                code = code.replace(
                    f"{name}[{idx}]",
                    f"'{string}'"
                )
        return code

if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        code = f.read()

    d = StringArrayDeobfuscator()
    d.extract_arrays(code)
    result = d.deobfuscate(code)

    print(result)
```

### Attribute Access Deobfuscation

```javascript
// Common obfuscation: _0x['prop'] instead of obj.prop
var _0x1a2b = { 'l': 'length', 'e': 'eval', 'c': 'cookie' };
var _0x3c4d = 'window';
var prop = _0x1a2b['l'];       // 'length'
var obj = window[_0x3c4d];     // window.window

// Deobfuscation approach:
// 1. Build mapping table of all _0x var references
// 2. Replace _0x['prop'] with actual property name
// 3. Note nested lookups

// Python helper
python3 -c "
import re
with open('obfuscated.js') as f:
    code = f.read()

# Find property access patterns
props = re.findall(r'(_0x[a-f0-9]+)\[\'([^\']+)\'\]', code)
for obj, prop in props[:20]:
    print(f'{obj}[\'{prop}\']')
"
```

---

## PRACTICAL DEOBFUSCATION EXAMPLES

### Example 1: Simple String Array

```javascript
// Input (obfuscated):
var _0x1a2b=['api','users','profile','admin','/v1/','/v2/','key','secret'];
var _0x3c4d=function(_0x5e6f,_0x7g8h){return _0x1a2b[_0x5e6f-0x5a];};
var url=_0x3c4d(0x5e)+_0x3c4d(0x5f)+_0x3c4d(0x61);

// Manual deobfuscation:
// _0x3c4d(0x5e) = _0x1a2b[4] = '/v1/'
// _0x3c4d(0x5f) = _0x1a2b[5] = '/v2/'
// _0x3c4d(0x61) = _0x1a2b[7] = 'secret'

// Result: url = '/v1//v2/secret'

// Quick script:
python3 -c "
arr = ['api','users','profile','admin','/v1/','/v2/','key','secret']
def get(i): return arr[i - 0x5a]
print(get(0x5e) + get(0x5f) + get(0x61))
"
```

### Example 2: Hex-Encoded eval

```javascript
// Input (obfuscated):
eval('\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x29\x20\x7b\x0a\x20\x20\x20\x20\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67\x28\x27\x68\x65\x6c\x6c\x6f\x27\x29\x3b\x0a\x7d\x28\x29\x3b');

// Decode:
echo -n '\x66\x75\x6e\x63\x74\x69\x6f\x6e' | xxd -r -p
# Output: function

// Full decode:
python3 -c "print('\x66\x75\x6e\x63\x74\x69\x6f\x6e\x20\x28\x29\x20\x7b\x0a\x20\x20\x20\x20\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x6c\x6f\x67\x28\x27\x68\x65\x6c\x6c\x6f\x27\x29\x3b\x0a\x7d\x28\x29\x3b')"
# Output: function () {
#         console.log('hello');
#       }();
```

### Example 3: Variable Name Recovery

```javascript
// Input (obfuscated):
function _0x1a2b(_0x3c4d) {
  var _0x5e6f = _0x3c4d['split']('');
  for (var _0x7g8h = 0; _0x7g8h < _0x5e6f['length']; _0x7g8h++) {
    _0x5e6f[_0x7g8h] = String['fromCharCode'](_0x5e6f[_0x7g8h]['charCodeAt'](0x0) ^ 0x5a);
  }
  return _0x5e6f['join']('');
}

// Analysis:
// 1. _0x1a2b takes a parameter, splits it → XOR decoding function
// 2. Each char XOR'd with 0x5a
// 3. Result joined back

// deobfuscate:
python3 -c "
def xor_decode(s, key=0x5a):
    return ''.join(chr(ord(c) ^ key) for c in s)

encoded = 'encrypted_string_here'
print(xor_decode(encoded))
"
```

### Example 4: Base64 Obfuscation

```javascript
// Input (obfuscated):
(function() {
  var _0x1a2b = 'YWJjZGVm';
  var _0x3c4d = 'ZGVm';
  function _0x5e6f(str) {
    return atob(str);
  }
  console.log(_0x5e6f(_0x1a2b) + _0x5e6f(_0x3c4d));
})();

// Decode:
echo 'YWJjZGVm' | base64 -d
# Output: abcdef
echo 'ZGVm' | base64 -d
# Output: def

// Combined: 'abcdef' + 'def' = 'abcdefdef'

// Deobfuscation script:
python3 -c "
import base64
print(base64.b64decode('YWJjZGVm').decode() + base64.b64decode('ZGVm').decode())
"
```

---

## VM EMULATION AND DEEPER ANALYSIS

### JavaScript VM Emulation

```javascript
// When code is heavily VM-obfuscated:
// Strategy: Emulate the VM in Python/Node

// VM skeleton:
var vm_state = {
  opcodes: [],
  stack: [],
  scope: {},
  memory: {},
  pc: 0,
};

// Read obfuscated opcodes
var _0xopcodes = [0x00, 0x01, 0x02, ...];

// Emulate in Python:
python3 -c "
class VM:
    def __init__(self, opcodes):
        self.opcodes = opcodes
        self.pc = 0
        self.stack = []
        self.scope = {}

    def run(self):
        while self.pc < len(self.opcodes):
            opcode = self.opcodes[self.pc]
            self.execute(opcode)
            self.pc += 1

    def execute(self, opcode):
        if opcode == 0x00:  # PUSH_STRING
            self.pc += 1
            idx = self.opcodes[self.pc]
            self.stack.append(strings[idx])
        elif opcode == 0x01:  # LOAD_VAR
            # ...
        elif opcode == 0x02:  # CALL
            fn = self.stack.pop()
            # ...
"
```

### Dynamic Analysis via Instrumentation

```javascript
// Instrument the obfuscated code to log every operation

// Intercept eval:
var originalEval = eval;
eval = function(code) {
  console.log('[EVAL]', code);
  return originalEval(code);
};

// Intercept Function constructor:
var originalFunction = Function;
window.Function = function() {
  console.log('[FUNCTION]', arguments);
  return originalFunction.apply(this, arguments);
};

// Hook console.log to capture output:
var logs = [];
var originalLog = console.log;
console.log = function(...args) {
  logs.push(args);
  originalLog.apply(console, args);
};

// Monitor variable assignments:
const _0xwatch = new Proxy({}, {
  set(target, key, value) {
    console.log(`[ASSIGN] ${key} = ${JSON.stringify(value)}`);
    target[key] = value;
    return true;
  }
});
```

---

## RECONSTRUCTING BUSINESS LOGIC

### Extracting API Endpoints

```python
# After deobfuscation, look for patterns:
import re

with open('deobfuscated.js') as f:
    code = f.read()

# Find fetch() calls
fetch_pattern = r'fetch\(["\\']([^"\\']+)["\\']\)'
fetches = re.findall(fetch_pattern, code)
print("Fetch endpoints:", fetches)

# Find AJAX calls
ajax_pattern = r'\\$\\.(get|post|put|delete|ajax)\\(["\\']([^"\\']+)["\\']\\)'
ajaxes = re.findall(ajax_pattern, code)
print("AJAX endpoints:", ajaxes)

# Find WebSocket URLs
ws_pattern = r'new WebSocket\\(["\\']([^"\\']+)["\\']\\)'
websockets = re.findall(ws_pattern, code)
print("WebSocket URLs:", websockets)

# Find environment/config
env_pattern = r'(API_URL|BASE_URL|ENDPOINT)\\s*[:=]\\s*["\\']([^"\\']+)["\\']'
envs = re.findall(env_pattern, code)
print("Environment vars:", envs)
```

### Recovering Original Logic

```python
# Simple Python deobfuscator for string array pattern

import re

class StringArrayDeobfuscator:
    def __init__(self, code):
        self.code = code
        self.strings = {}

    def extract_arrays(self):
        """Find and parse string arrays"""
        pattern = r'var ([_0-9a-zA-Z]+)\\s*=\\s*\\[(.*?)\\];'
        matches = re.findall(pattern, self.code, re.DOTALL)

        for name, content in matches:
            strings = re.findall(r"'([^']*)'", content)
            if strings:
                self.strings[name] = strings

    def deobfuscate(self):
        """Replace array lookups with actual strings"""
        for name, strings in self.strings.items():
            for idx, string in enumerate(strings):
                self.code = self.code.replace(
                    f"{name}[{idx}]",
                    f"'{string}'"
                )
        return self.code

# Usage:
with open('obfuscated.js') as f:
    code = f.read()

d = StringArrayDeobfuscator(code)
d.extract_arrays()
clean = d.deobfuscate()
print(clean)
```

---

## DEOBFUSCATION SECURITY FINDINGS

### What to Look For After Deobfuscation

```javascript
// 1. Hidden admin endpoints
/api/v1/admin/*    <- referenced in obfuscated code
/api/v2/internal/* <- hidden from crawlers

// 2. Exposed secrets
const API_KEY = 'sk_live_...';  // Stripe live key in production
const AWS_KEY = 'AKIA...';      // AWS key (check if active)

// 3. Authorization bypasses
if (url.includes('/admin') && !user.isAdmin) {
  // Commented out check!
  // return 403;
}

// 4. Hardcoded credentials
const DB_PASS = 'admin123';
const JWT_SECRET = 'secret123';

// 5. Debug endpoints
if (DEBUG_MODE) {
  routes.push('/api/debug/users');
  routes.push('/api/debug/queries');
}

// 6. Feature flags
const FEATURES = {
  NEW_BILLING: false,      // Might enable free tier bypass
  ADMIN_PANEL: true,       // Admin panel accessible via URL
  SKIP_AUTH: false,        // Set true = no auth
};

// 7. SSTI sink (template injection)
function renderTemplate(template, data) {
  return template.replace(/\\{\\{(.*?)\\}\\}/g, function(match, expr) {
    return eval(expr);  // DANGEROUS: SSTI
  });
}
```

---

## JS ANALYSIS SECURITY PATTERNS

### Dangerous Patterns to Report

```bash
# InnerHTML assignment
grep -rEo 'innerHTML\\s*=\\s*[^;]+' *.js | grep -v 'textContent'
grep -rEo 'outerHTML\\s*=\\s*[^;]+' *.js

# DOM XSS sinks
grep -rEo 'document\\.write\\([^)]+\\)' *.js
grep -rEo 'eval\\([^)]+\\)' *.js
grep -rEo 'setTimeout\\([^)]+\\)' *.js
grep -rEo 'setInterval\\([^)]+\\)' *.js

# Location manipulation
grep -rEo 'location\\s*=\\s*[^;]+' *.js
grep -rEo 'location\\.href\\s*=\\s*[^;]+' *.js
grep -rEo 'location\\.replace\\([^)]+\\)' *.js

# PostMessage without origin check
grep -rEo 'addEventListener\\(["\\`]message["\\`]' *.js
grep -rEo '\\.onmessage\\s*=' *.js

# Prototype pollution
grep -rEo 'Object\\.assign\\([^)]+__proto__[^)]*\\)' *.js
grep -rEo '\\.\\.__proto__' *.js
grep -rEo 'constructor.*prototype' *.js

# Unsafe deserialization
grep -rEo 'JSON\\.parse\\([^)]+\\)' *.js

# Insecure WebSocket
grep -rEo 'new WebSocket\\([^)]+\\)' *.js

# Hardcoded sensitive data
grep -rEo '(password|secret|key|token)\\s*[:=]\\s*["\\`][^"\\`]+["\\`]' *.js
```

### JS File Insights for Bug Bounty

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
grep -rEo '\\$\\.ajax\\(\\{[^}]+\\}\\)' *.js
grep -oE "url:\\s*['\"][^'\"]+['\"]" *.js

# Endpoint discovery
grep -oE "url:\\s*['\"][^'\"]+['\"]" *.js | sort -u

# Method detection
grep -oE "type:\\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]" *.js

# Data extraction
grep -oE "data:\\s*\\{[^}]+\\}" *.js | head -20
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
grep -rEo '(merge|clone|extend|assign|deepMerge)\\([^)]+\\)' *.js | head -20

# Look for __proto__ or constructor manipulation
grep -rEo '__proto__' *.js
grep -rEo 'constructor.*prototype' *.js

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
grep -oE 'https?://[a-zA-Z0-9.-]+\\.(internal|corp|dev|st|aging)[a-zA-Z0-9.-]*' *.js
grep -oE '(API_URL|BASE_URL|ENV|ENVIRONMENT|NODE_ENV|APP_ENV)\\s*[:=]\\s*["\\`][^"\\`]+["\\`]' *.js

# Debug flags
grep -rEo '(DEBUG|ENABLE_DEBUG|SHOW_DEBUG)\\s*[:=]\\s*(true|false)' *.js

# Internal IPs
grep -oE '(localhost|127\\.0\\.0\\.1|10\\.|172\\.(1[6-9]|2\\d|3[01])\\.|192\\.168\\.)' *.js

# Credential information in JS
grep -oE '(user|pass|admin|root)\\s*[:=]\\s*["\\`][^"\\`]+["\\`]' *.js
```

### API Documentation in JS

```bash
# OpenAPI/Swagger in JS
grep -oE '"(swagger|openapi|api-docs|api/docs)[^"]*"' *.js
grep -oE "'(swagger|openapi|api-docs|api/docs)[^']*'" *.js

# GraphQL introspection (check for enabled)
grep -oE '(__schema|__type)\\s*:' *.js

# JSDoc comments
grep -oE '/\\*\\*[\\s\\S]*?\\*/' *.js | grep -iE '(api|endpoint|route|todo|fixme|hack|bug)'
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
