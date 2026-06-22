const fs = require('fs');
const path = require('path');
const vm = require('vm');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node multi-packer-resolver.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

const PACKERS = [
  { name: 'Packer (eval+p,a,c,k,e,d)', re: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)/, severity: 10 },
  { name: 'Base64 encoded eval', re: /eval\s*\(\s*atob\s*\(/, severity: 7 },
  { name: 'Double eval', re: /eval\s*\(\s*eval\s*\(/, severity: 8 },
  { name: 'Nested fromCharCode', re: /String\.fromCharCode[\s\S]{50,}String\.fromCharCode/, severity: 5 },
  { name: 'Chained atob', re: /atob\s*\([^)]+\)\s*\+\s*atob\s*\(/, severity: 6 },
  { name: 'Recursive decode', re: /decodeURIComponent\s*\(\s*decodeURIComponent\s*\(/, severity: 7 },
  { name: 'Eval in setTimeout', re: /setTimeout\s*\(\s*["'`][^"'`]*eval\s*\(/, severity: 8 },
  { name: 'Function() inside eval', re: /eval\s*\([^)]*new\s+Function\s*\(/, severity: 9 },
];

function resolvePackers(inputCode, maxIterations = 20) {
  const layers = [];
  let current = inputCode;
  let prevLen = -1;
  let resolvedContent = null;

  for (let iter = 0; iter < maxIterations && current.length !== prevLen; iter++) {
    prevLen = current.length;
    let found = false;

    const packerRe = /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)\s*\{[\s\S]{100,}?\}\s*\(([^)]+)\s*\)\s*\)/;
    const pm = packerRe.exec(current);
    if (pm) {
      try {
        const params = pm[1].split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
        const p = params[0] || '', a = parseInt(params[1]) || 0, c = parseInt(params[2]) || 0;
        const k = params[3] ? params[3].replace(/^\[|\]$/g, '').split('|') : [];
        const script = new vm.Script(`"use strict"; var p=${JSON.stringify(p)},a=${a},c=${c},k=${JSON.stringify(k)};` + pm[0], { timeout: 1000 });
        const result = script.runInNewContext({}, { timeout: 1000 });
        if (typeof result === 'string' && result.length > 50) {
          layers.push({ type: 'Packer (eval)', iteration: iter, outputLen: result.length });
          current = result; found = true; resolvedContent = result;
        }
      } catch (e) {
        layers.push({ type: 'Packer (eval) FAILED', iteration: iter, error: e.message });
      }
    }

    if (!found) {
      const atobEvalRe = /eval\s*\(\s*atob\s*\(\s*["']([^"']+)["']\s*\)\s*\)/g;
      let m;
      while ((m = atobEvalRe.exec(current)) !== null) {
        try {
          const decoded = Buffer.from(m[1], 'base64').toString('utf-8');
          if (decoded.length > 20) {
            current = current.replace(m[0], decoded);
            layers.push({ type: 'atob→eval', iteration: iter, outputLen: decoded.length });
            found = true; resolvedContent = current;
          }
        } catch (e) {}
      }
    }

    if (!found && iter < 5) {
      const doubleEvalRe = /eval\s*\(\s*eval\s*\(\s*["'`]([^"'`]{20,})["'`]\s*\)\s*\)/g;
      let m;
      while ((m = doubleEvalRe.exec(current)) !== null) {
        try {
          const inner = new vm.Script(m[1], { timeout: 200 });
          const innerResult = inner.runInNewContext({}, { timeout: 200 });
          if (typeof innerResult === 'string' && innerResult.length > 10) {
            current = current.replace(m[0], innerResult);
            layers.push({ type: 'double eval', iteration: iter });
            found = true; resolvedContent = current;
          }
        } catch (e) {}
      }
    }
  }

  return {
    layers,
    totalLayers: layers.length,
    resolved: resolvedContent !== null,
    output: resolvedContent || current,
    packersDetected: PACKERS.filter(p => p.re.test(inputCode)).map(p => p.name),
  };
}

if (isCLI) {
  console.log(`\n========================================`);
  console.log(`  Multi-Packer Chain Resolution`);
  console.log(`========================================\n`);
  const packersFound = PACKERS.filter(p => p.re.test(code));
  console.log(`  Packers detected: ${packersFound.length}`);
  packersFound.forEach(p => console.log(`    - ${p.name}`));
  if (packersFound.length === 0) { console.log('  No known packers detected.\n'); process.exit(0); }

  const result = resolvePackers(code);
  console.log(`\n  Layers resolved: ${result.layers.length}`);
  result.layers.slice(0, 10).forEach((l, i) => {
    const detail = l.outputLen ? `output: ${l.outputLen} chars` : l.error ? `error: ${l.error.substring(0, 60)}` : '';
    console.log(`    Layer ${i+1}: ${l.type} (${detail})`);
  });
  if (result.layers.length > 10) console.log(`    ... and ${result.layers.length - 10} more`);

  if (result.resolved) {
    const reduction = ((1 - result.output.length / code.length) * 100).toFixed(1);
    console.log(`\n  Input:  ${code.length} chars`);
    console.log(`  Output: ${result.output.length} chars`);
    console.log(`  Reduction: ${reduction}%`);
  }
  console.log('');
}

module.exports = { PACKERS, resolvePackers };
