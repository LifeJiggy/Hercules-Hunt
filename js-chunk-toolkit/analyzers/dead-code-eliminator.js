const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node dead-code-eliminator.js <file.js> [--output cleaned.js]'); process.exit(1); }

const inputFile = args[0];
const outFlag = args.indexOf('--output');
const outputFile = outFlag > -1 && args[outFlag + 1] ? args[outFlag + 1] : null;

const loaded = harden.safeLoadFile(inputFile);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }

let code = loaded.content;
let totalStripped = 0;
let changes = [];

// Constants for branch analysis
const ALWAYS_TRUE = new Set([
  'true', '1', '!![]', '"1"', "'1'", '!0', '"true"', "'true'",
  '1===1', '"a"==="a"', 'typeof window', 'typeof document',
]);
const ALWAYS_FALSE = new Set([
  'false', '0', '!1', '""', "''", 'null', 'undefined', 'void 0',
  '![]', '1===2', '"a"==="b"',
]);

function stripSection(start, end, label) {
  const removed = code.substring(start, end);
  code = code.substring(0, start) + code.substring(end);
  totalStripped += removed.length;
  const line = removed.substring(0, 100).split('\n')[0].substring(0, 60);
  changes.push({ type: label, removed: removed.length, line: line.substring(0, 60), lineNum: loaded.content.substring(0, start).split('\n').length });
}

// Pattern 1: Empty catch blocks
function stripEmptyCatches() {
  const re = /catch\s*\([^)]*\)\s*\{\s*\}/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    stripSection(m.index, m.index + m[0].length, 'empty_catch');
  }
}

// Pattern 2: Empty function bodies (noop)
function stripNoopFunctions() {
  const re = /function\s*\w*\s*\(\)\s*\{\s*\}/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    stripSection(m.index, m.index + m[0].length, 'noop_function');
  }
  const iifeRe = /!?\s*function\s*\(\)\s*\{\s*\}\s*\(\)/g;
  while ((m = iifeRe.exec(code)) !== null) {
    stripSection(m.index, m.index + m[0].length, 'noop_iife');
  }
}

// Pattern 3: Boolean cast noise (!![], !!, +!+[])
function stripBooleanCasts() {
  const re = /!!\s*\[\s*\]/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    stripSection(m.index, m.index + m[0].length, 'bool_cast_true');
  }
}

// Pattern 4: Constant if branches
function stripConstantIfs() {
  const ifRe = /if\s*\(([^)]+)\)\s*\{([^}]*)\}\s*(?:else\s*\{([^}]*)\})?/g;
  let m;
  while ((m = ifRe.exec(code)) !== null) {
    const cond = m[1].trim();
    const ifBody = m[2] || '';
    const elseBody = m[3] || '';
    if (ALWAYS_TRUE.has(cond)) {
      if (elseBody) {
        stripSection(m.index + m[0].indexOf(elseBody), m.index + m[0].indexOf(elseBody) + elseBody.length + 2, 'dead_else_branch');
      }
    } else if (ALWAYS_FALSE.has(cond)) {
      if (elseBody) {
        const ifEnd = m.index + m[0].indexOf('}') + 1;
        const elseStart = ifEnd;
        stripSection(m.index, elseStart, 'dead_if_branch_false');
      } else {
        stripSection(m.index, m.index + m[0].length, 'dead_if_branch');
      }
    }
  }
}

// Pattern 5: Useless ternary with known constants
function stripConstantTernary() {
  const terrRe = /(true|false|1|0|null|undefined)\s*\?\s*['"`][^'"`]*['"`]\s*:\s*['"`][^'"`]*['"`]/g;
  let m;
  while ((m = terrRe.exec(code)) !== null) {
    if (m[1] === 'true' || m[1] === '1') {
      const valMatch = m[0].match(/\?\s*(['"`][^'"`]*['"`])/);
      if (valMatch) {
        stripSection(m.index, m.index + m[0].length, 'const_ternary_true');
      }
    }
  }
}

// Pattern 6: Self-assignment (x = x)
function stripSelfAssignment() {
  const re = /(\w+)\s*=\s*\1\s*;/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    if (!['true', 'false', 'null', 'undefined', 'this'].includes(m[1])) {
      stripSection(m.index, m.index + m[0].length, 'self_assignment');
    }
  }
}

// Pattern 7: Empty array/object literals as statements
function stripEmptyLiterals() {
  const re = /\[\s*\]\s*;|\[\s*\]\s*,/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const before = code.substring(Math.max(0, m.index - 50), m.index).trim();
    if (!before.endsWith('=') && !before.endsWith(':') && !before.endsWith('return') && !before.endsWith(',')) {
      stripSection(m.index, m.index + m[0].length, 'empty_array_literal');
    }
  }
}

// Pattern 8: Redundant while(true) with break as dead code container
function detectDeadWhileBlocks() {
  const re = /while\s*\(\s*true\s*\)\s*\{/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const bodyStart = m.index + m[0].length;
    const bodyEnd = harden._extractBracketBlockCustom ? -1 : findMatchingBrace(code, bodyStart);
    if (bodyEnd === -1) continue;
    const body = code.substring(bodyStart, bodyEnd - 1);
    if (!body.includes('break') && !body.includes('return')) {
      stripSection(m.index, bodyEnd, 'dead_while_true');
    }
  }
}

function findMatchingBrace(content, startIdx) {
  if (content[startIdx] !== '{') return -1;
  let depth = 0;
  let inStr = false;
  let strChar = null;
  for (let i = startIdx; i < content.length && i < startIdx + 50000; i++) {
    const ch = content[i];
    if (inStr) { if (ch === '\\') i++; else if (ch === strChar) inStr = false; continue; }
    if (ch === '"' || ch === "'" || ch === '`') { inStr = true; strChar = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return i + 1; }
  }
  return -1;
}

harden._extractBracketBlockCustom = findMatchingBrace;

const startLen = code.length;

let prevLen = -1;
let iteration = 0;
while (code.length !== prevLen && iteration < 10) {
  prevLen = code.length; iteration++;
  stripEmptyCatches();
  stripNoopFunctions();
  stripBooleanCasts();
  stripConstantIfs();
  stripConstantTernary();
  stripSelfAssignment();
  stripEmptyLiterals();
}

const ratio = startLen > 0 ? ((1 - code.length / startLen) * 100).toFixed(1) : '0.0';

console.log(`\n========================================`);
console.log(`  Dead Code Eliminator`);
console.log(`========================================`);
console.log(`  Input file:  ${path.basename(inputFile)}`);
console.log(`  Input size:  ${startLen} chars`);
console.log(`  Output size: ${code.length} chars`);
console.log(`  Reduction:   ${ratio}%`);
console.log(`  Iterations:  ${iteration}`);
console.log(`  Stripped:    ${totalStripped} chars`);
console.log('');
if (changes.length > 0) {
  const byType = {};
  for (const c of changes) { byType[c.type] = (byType[c.type] || 0) + 1; }
  console.log('  Removed by type:');
  Object.entries(byType).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
    console.log(`    ${type.padEnd(25)}: ${count}`);
  });
  console.log('');
  console.log('  Top 10 removals (by size):');
  changes.sort((a, b) => b.removed - a.removed).slice(0, 10).forEach((c, i) => {
    console.log(`    ${(i+1).toString().padStart(2)}. ${c.type.padEnd(22)} ${c.removed}b  line ${c.lineNum}`);
  });
} else {
  console.log('  No dead code found.');
}
console.log('');

if (outputFile) {
  const dir = path.dirname(outputFile);
  if (dir) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputFile, code, 'utf-8');
  console.log(`[OK] Cleaned output written to ${outputFile}\n`);
}
