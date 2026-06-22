const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node closure-resolver.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

function resolveClosures(inputCode) {
  const closures = [];
  const funcRe = /function\s*(\w*)\s*\(([^)]*)\)\s*\{/g;
  let m;
  const outerVars = new Set();
  const outerRe = /(?:var|let|const)\s+(\w+)\s*=/g;
  let vm;
  while ((vm = outerRe.exec(inputCode)) !== null) outerVars.add(vm[1]);

  while ((m = funcRe.exec(inputCode)) !== null) {
    const fnName = m[1] || '(anonymous)';
    const params = m[2].split(',').map(s => s.trim()).filter(Boolean);
    const paramSet = new Set(params);
    const start = m.index;
    const end = findBlockEnd(inputCode, m.index + m[0].length - 1);
    const body = inputCode.substring(start, end);

    const refRe = /\b(\w+)\b/g;
    let rm;
    const usedVars = new Set();
    while ((rm = refRe.exec(body)) !== null) {
      if (!paramSet.has(rm[1]) && !['if','else','for','while','do','switch','case','break','continue','return','var','let','const','function','new','this','typeof','instanceof','void','delete','in','of','try','catch','finally','throw','undefined','null','true','false','NaN'].includes(rm[1])) {
        usedVars.add(rm[1]);
      }
    }

    const captured = [...usedVars].filter(v => outerVars.has(v) && !paramSet.has(v));
    if (captured.length > 0) {
      closures.push({ function: fnName, params, captured, line: inputCode.substring(0, m.index).split('\n').length });
    }
  }

  return { closures, total: closures.length };
}

function findBlockEnd(str, start) {
  let depth = 1;
  for (let i = start; i < str.length; i++) {
    if (str[i] === '{') depth++;
    if (str[i] === '}') { depth--; if (depth === 0) return i + 1; }
  }
  return str.length;
}

if (isCLI) {
  const result = resolveClosures(code);
  console.log(`\n========================================`);
  console.log(`  Closure Variable Resolution`);
  console.log(`========================================`);
  console.log(`  Closures found: ${result.total}`);
  if (result.closures.length > 0) {
    console.log('\n  Captured variables:');
    result.closures.slice(0, 15).forEach(c => {
      console.log(`    ${c.function}(${c.params.join(', ')}) → captures [${c.captured.join(', ')}] (line ${c.line})`);
    });
  } else {
    console.log('  No closure variables captured.');
  }
  console.log('');
}

module.exports = { resolveClosures };
