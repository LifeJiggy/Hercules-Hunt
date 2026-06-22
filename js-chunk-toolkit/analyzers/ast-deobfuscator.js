const fs = require('fs');
const path = require('path');
const vm = require('vm');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let inputFile, outputFile, code;

if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node ast-deobfuscator.js <file.js> [--output cleaned.js]'); process.exit(1); }
  inputFile = args[0];
  const outFlag = args.indexOf('--output');
  outputFile = outFlag > -1 && args[outFlag + 1] ? args[outFlag + 1] : null;
  const loaded = harden.safeLoadFile(inputFile);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

function deobfuscateAST(inputCode, options = {}) {
  const maxIterations = options.iterations || 20;
  let code = inputCode;
  let transforms = [];
  let totalChanged = 0;
  const origLen = code.length;

function sandboxEval(expr) {
  try {
    const script = new vm.Script(`(() => (${expr}))()`);
    const result = script.runInNewContext({}, { timeout: 100, breakOnSigint: true });
    if (typeof result === 'string' || typeof result === 'number' || typeof result === 'boolean') return result;
    return null;
  } catch { return null; }
}

// Transform 1: Constant string concatenation folding
function foldStringConcat() {
  const re = /(["'`][^"'`]{0,50}["'`])\s*\+\s*(["'`][^"'`]{0,50}["'`])/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const folded = sandboxEval(m[0]);
    if (folded !== null && typeof folded === 'string') {
      const replacement = JSON.stringify(folded);
      if (replacement.length < m[0].length) {
        code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
        transforms.push({ name: 'string_concat_fold', before: m[0].substring(0, 40), after: replacement.substring(0, 40), saved: m[0].length - replacement.length });
        changed = true; totalChanged++;
      }
    }
  }
  return changed;
}

// Transform 2: Binary expression folding (math on constants)
function foldBinaryExpr() {
  const re = /(\d+(?:\.\d+)?)\s*([+\-*/%])\s*(\d+(?:\.\d+)?)/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    if (m[2] === '+' && (m[1].length > 3 || m[3].length > 3)) continue;
    const folded = sandboxEval(`(${m[1]} ${m[2]} ${m[3]})`);
    if (folded !== null && typeof folded === 'number') {
      const replacement = String(folded);
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'binary_fold', before: m[0].substring(0, 40), after: replacement, saved: m[0].length - replacement.length });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 3: Boolean expression folding
function foldBooleanExpr() {
  const re = /(!+\s*(?:true|false|1|0|null|undefined|!!\[\]|\[\]))/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const folded = sandboxEval(m[1]);
    if (folded !== null && typeof folded === 'boolean') {
      const replacement = folded ? '!0' : '!1';
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'bool_fold', before: m[0].substring(0, 40), after: replacement });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 4: Array access on known constant arrays
function foldArrayAccess() {
  const arrRe = /\[([\d,]+)\]\s*\[\s*(\d+)\s*\]/g;
  let changed = false;
  let m;
  while ((m = arrRe.exec(code)) !== null) {
    const folded = sandboxEval(m[0]);
    if (folded !== null && typeof folded !== 'object') {
      const replacement = JSON.stringify(folded);
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'array_access_fold', before: m[0].substring(0, 40), after: replacement.substring(0, 40) });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 5: Ternary with constant condition
function foldConstantTernary() {
  const re = /(true|false|!0|!1)\s*\?\s*([^:]+?)\s*:\s*([^,;)]+?)(?=[,;)\]})])/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const cond = m[1] === 'true' || m[1] === '!0';
    const val = cond ? m[2].trim() : m[3].trim();
    const folded = sandboxEval(val);
    if (folded !== null) {
      const replacement = JSON.stringify(folded);
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'const_ternary', before: m[0].substring(0, 50), after: replacement.substring(0, 40) });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 6: ![] → false, !![] → true, etc
function foldJSFuckPrimitives() {
  const re = /(!+\s*\[\s*\])/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const folded = sandboxEval(m[1]);
    if (folded !== null && typeof folded === 'boolean') {
      const replacement = folded ? '!0' : '!1';
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'jsfuck_primitives', before: m[0], after: replacement });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 7: +[] → 0, +!+[] → 1, etc
function foldUnaryCoercion() {
  const re = /[+!]\s*\[\s*\]|~\[\s*\]/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const folded = sandboxEval(m[0]);
    if (folded !== null && typeof folded === 'number') {
      const replacement = String(folded);
      code = code.substring(0, m.index) + replacement + code.substring(m.index + m[0].length);
      transforms.push({ name: 'unary_coercion', before: m[0], after: replacement });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Transform 8: Dead if branch elimination (constant condition)
function eliminateDeadBranches() {
  const re = /if\s*\((![01]|true|false)\)\s*\{([^}]*)\}\s*(?:else\s*\{([^}]*)\})?/g;
  let changed = false;
  let m;
  while ((m = re.exec(code)) !== null) {
    const isTrue = m[1] === 'true' || m[1] === '!0' || m[1] === '1';
    const body = isTrue ? (m[2] || '') : (m[3] || '');
    const replacement = body;
    const start = m.index;
    const end = m.index + m[0].length;
    const origSection = code.substring(start, end);
    if (replacement.length < origSection.length - 4) {
      code = code.substring(0, start) + replacement + code.substring(end);
      transforms.push({ name: 'dead_branch_elim', before: origSection.substring(0, 50), after: replacement.substring(0, 40), saved: origSection.length - replacement.length });
      changed = true; totalChanged++;
    }
  }
  return changed;
}

// Run all transforms iteratively
let prevLen = -1;
let iteration = 0;
const stats = {};

while (code.length !== prevLen && iteration < 20) {
  prevLen = code.length; iteration++;
  const fns = [foldStringConcat, foldBinaryExpr, foldBooleanExpr, foldArrayAccess, foldConstantTernary, foldJSFuckPrimitives, foldUnaryCoercion, eliminateDeadBranches];
  for (const fn of fns) { try { fn(); } catch {} }
}

for (const t of transforms) { stats[t.name] = (stats[t.name] || 0) + 1; }

return {
  total: totalChanged,
  inputSize: origLen,
  outputSize: code.length,
  transforms,
  stats,
  output: code,
  iterations: iteration
};
}

if (isCLI) {
  const result = deobfuscateAST(code, { iterations: 20 });
  const ratio = result.inputSize > 0 ? ((1 - result.outputSize / result.inputSize) * 100).toFixed(2) : '0.00';
  console.log(`\n========================================`);
  console.log(`  AST Deobfuscation Engine`);
  console.log(`========================================`);
  console.log(`  Input:  ${result.inputSize} chars`);
  console.log(`  Output: ${result.outputSize} chars`);
  console.log(`  Reduction: ${ratio}%`);
  console.log(`  Iterations: ${result.iterations}`);
  console.log(`  Total transforms: ${result.total}`);
  console.log('');
  console.log('  Transforms applied:');
  Object.entries(result.stats).sort((a, b) => b[1] - a[1]).forEach(([name, count]) => {
    const saved = result.transforms.filter(t => t.name === name).reduce((s, t) => s + (t.saved || 0), 0);
    console.log(`    ${name.padEnd(25)}: ${count.toString().padStart(4)} (saved ${saved}b)`);
  });
  console.log('');
  if (outputFile) {
    fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
    fs.writeFileSync(outputFile, result.output, 'utf-8');
    console.log(`[OK] Deobfuscated output written to ${path.resolve(outputFile)}\n`);
  }
}

module.exports = { deobfuscateAST };
