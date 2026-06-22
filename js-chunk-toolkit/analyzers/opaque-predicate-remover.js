const fs = require('fs');
const path = require('path');
const vm = require('vm');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node opaque-predicate-remover.js <file.js>'); process.exit(1); }

const loaded = harden.safeLoadFile(args[0]);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
const code = loaded.content;

const OPQ_PATTERNS = [
  {
    name: 'typeof undefined === undefined',
    re: /typeof\s+\w+\s*===\s*['"]undefined['"]/g,
    resolve: 'true',
    confidence: 'HIGH'
  },
  {
    name: 'typeof undefined !== undefined',
    re: /typeof\s+\w+\s*!==\s*['"]undefined['"]/g,
    resolve: 'false',
    confidence: 'HIGH'
  },
  {
    name: '1 === 1',
    re: /\b(\d+)\s*===\s*\1\b(?!\s*\+\s*)/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '1 !== 1',
    re: /\b(\d+)\s*!==\s*\1\b(?!\s*\+\s*)/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '1 == 1',
    re: /\b(\d+)\s*==\s*\1\b(?!\s*\+\s*)/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '1 != 1',
    re: /\b(\d+)\s*!=\s*\1\b(?!\s*\+\s*)/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: 'false === false',
    re: /\b(false)\s*===\s*\1\b/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: 'true === true',
    re: /\b(true)\s*===\s*\1\b/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: 'false !== false',
    re: /\b(false)\s*!==\s*\1\b/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: 'true !== true',
    re: /\b(true)\s*!==\s*\1\b/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '!![] (true)',
    re: /!!\s*\[\s*\]/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '![] (false)',
    re: /!\[\s*\]/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '!!{} (true in JS)',
    re: /!!\s*\{\s*\}/g,
    resolve: 'true',
    confidence: 'CERTAIN'  
  },
  {
    name: '+[] === 0',
    re: /\+\s*\[\s*\]\s*===\s*0/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '+[] !== 0',
    re: /\+\s*\[\s*\]\s*!==\s*0/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '[] + [] === ""',
    re: /\[\s*\]\s*\+\s*\[\s*\]\s*===\s*""/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '[] + [] !== ""',
    re: /\[\s*\]\s*\+\s*\[\s*\]\s*!==\s*""/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '!!0 === false',
    re: /!!0\b/g,
    resolve: 'false',
    confidence: 'CERTAIN'
  },
  {
    name: '!!1 === true',
    re: /!![1-9]\d*\b/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '"" == false',
    re: /""\s*==\s*false/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '"" !== false',
    re: /""\s*!==\s*false/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '0 == false',
    re: /0\s*==\s*false/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: '0 !== false',
    re: /0\s*!==\s*false/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: 'null == undefined',
    re: /null\s*==\s*undefined/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  },
  {
    name: 'null !== undefined',
    re: /null\s*!==\s*undefined/g,
    resolve: 'true',
    confidence: 'CERTAIN'
  }
];

function removeOpaqueIfBlocks(code, findings) {
  let current = code;
  let changed = false;

  const blockRe = /if\s*\(\s*(true|false)\s*\)\s*\{([\s\S]*?)\}\s*(?:else\s*\{([\s\S]*?)\})?/g;
  let m;
  while ((m = blockRe.exec(current)) !== null) {
    const cond = m[1];
    const ifBody = m[2];
    const elseBody = m[3];
    const replacement = cond === 'true' ? ifBody : (elseBody || '');
    const before = current.substring(0, m.index);
    const after = current.substring(m.index + m[0].length);
    current = before + replacement + after;
    findings.push({ type: `if(${cond}) branch elimination`, confidence: 'CERTAIN', removed: m[0].substring(0, 60) });
    changed = true;
    blockRe.lastIndex = 0;
  }

  const ternRe = /\?\s*(['"`][^'"`]{0,50}['"`]|true)\s*:\s*(['"`][^'"`]{0,50}['"`]|false)\s*;/g;
  m = ternRe.exec(current);
  if (m) {
    const directValue = m[1];
    current = current.replace(m[0], ` ${directValue};`);
    findings.push({ type: 'always-true ternary simplified', confidence: 'CERTAIN', removed: m[0].substring(0, 60) });
    changed = true;
  }

  return { code: current, changed };
}

function removeOpaquePredicates(code) {
  let current = code;
  let totalRemoved = 0;
  const findings = [];

  for (const opq of OPQ_PATTERNS) {
    opq.re.lastIndex = 0;
    let m;
    while ((m = opq.re.exec(current)) !== null) {
      current = current.replace(m[0], opq.resolve);
      totalRemoved++;
      findings.push({ pattern: opq.name, replacement: opq.resolve, confidence: opq.confidence, match: m[0] });
      opq.re.lastIndex = 0;
    }
  }

  const blockResult = removeOpaqueIfBlocks(current, findings);
  current = blockResult.code;
  if (blockResult.changed) totalRemoved += findings.length - (findings.length - (totalRemoved > 0 ? 1 : 0));

  return { code: current, total: totalRemoved, findings };
}

console.log('\n========================================');
console.log('  Opaque Predicate Removal');
console.log('========================================\n');

const result = removeOpaquePredicates(code);
if (result.total > 0) {
  console.log(`  Opaque predicates removed: ${result.total}`);
  console.log(`  Input size:  ${code.length} chars`);
  console.log(`  Output size: ${result.code.length} chars`);
  console.log(`  Reduction:   ${((1 - result.code.length / code.length) * 100).toFixed(2)}%\n`);

  const byConfidence = {};
  for (const f of result.findings) {
    byConfidence[f.confidence] = (byConfidence[f.confidence] || 0) + 1;
  }
  console.log('  By confidence:');
  Object.entries(byConfidence).forEach(([k, v]) => console.log(`    ${k}: ${v}`));

  console.log('\n  Top removals:');
  result.findings.slice(0, 15).forEach(f => console.log(`    ${f.pattern} -> ${f.replacement || 'N/A'} [${f.confidence}]`));

  if (result.findings.length > 15) {
    console.log(`    ... and ${result.findings.length - 15} more`);
  }

  console.log(`\n  [32] Status: ${result.total > 0 ? 'PREDICATES_REMOVED' : 'CLEAN'}`);
} else {
  console.log('  No opaque predicates detected.\n');
  console.log('  [32] Status: CLEAN\n');
}

module.exports = { OPQ_PATTERNS, removeOpaquePredicates };
