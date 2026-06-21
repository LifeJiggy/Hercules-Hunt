const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node prototype-pollution-finder.js <file.js>'); process.exit(1); }

const loaded = harden.safeLoadFile(args[0]);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
const code = loaded.content;

const PP_PATTERNS = [
  {
    name: '__proto__ direct assignment',
    re: /__proto__\s*=/g,
    severity: 'CRITICAL',
    note: 'Direct prototype assignment — immediate pollution'
  },
  {
    name: '__proto__ in bracket notation',
    re: /\[\s*['"]__proto__['"]\s*\]/g,
    severity: 'CRITICAL',
    note: 'Bracket notation proto access — obfuscated'
  },
  {
    name: 'constructor.prototype',
    re: /constructor\.prototype\s*[.=]/g,
    severity: 'HIGH',
    note: 'Constructor prototype manipulation'
  },
  {
    name: 'Object.assign merge pattern',
    re: /Object\.assign\s*\(\s*\{\s*\}[^)]*\)/g,
    severity: 'HIGH',
    note: 'Object.assign({}, userInput) — if userInput has __proto__, pollutes'
  },
  {
    name: 'lodash _.merge',
    re: /_\.merge\s*\(/g,
    severity: 'CRITICAL',
    note: 'lodash merge is classic PP gadget — CVE-2019-10744'
  },
  {
    name: 'lodash _.set',
    re: /_\.set\s*\(/g,
    severity: 'HIGH',
    note: 'lodash set with user-controlled path → PP'
  },
  {
    name: 'lodash _.defaultsDeep',
    re: /_\.defaultsDeep\s*\(/g,
    severity: 'HIGH',
    note: 'lodash defaultsDeep is merge-like'
  },
  {
    name: 'jQuery $.extend(true)',
    re: /\$\.extend\s*\(\s*true\s*,/g,
    severity: 'CRITICAL',
    note: 'Deep extend with user object — CVE-2019-11358'
  },
  {
    name: 'spread merge pattern',
    re: /\{\.\.\.\w+\s*[,}]/g,
    severity: 'MEDIUM',
    note: 'Object spread with user-controlled object may propagate __proto__'
  },
  {
    name: 'JSON.parse + merge',
    re: /JSON\.parse\s*\([^)]*\)\s*\)/g,
    severity: 'MEDIUM',
    note: 'Parsed JSON fed into merge — if __proto__ in string, pollutes'
  },
  {
    name: 'for..in assignment',
    re: /for\s*\([^)]+in[^)]+\)\s*\{[^}]*\[\s*\w+\s*\]\s*=/g,
    severity: 'MEDIUM',
    note: 'for..in loop assigning properties — classic PP pattern'
  },
  {
    name: 'Object.defineProperty __proto__',
    re: /Object\.defineProperty\s*\([^)]*__proto__/g,
    severity: 'HIGH',
    note: 'Explicit defineProperty on __proto__'
  },
];

const SINKS_AFTER_PP = [
  { name: 'template compilation', re: /\.compile\s*\(|\.render\s*\(/g, chain: 'PP → SSTI' },
  { name: 'eval/Function', re: /\beval\s*\(|new\s+Function\s*\(/g, chain: 'PP → RCE' },
  { name: 'innerHTML write', re: /\.innerHTML\s*=/g, chain: 'PP → XSS' },
  { name: 'fetch/XMLHttpRequest', re: /\bfetch\s*\(|\.open\s*\(/g, chain: 'PP → SSRF' },
  { name: 'require/import', re: /\brequire\s*\(|import\s*\(/g, chain: 'PP → RCE' },
  { name: 'child_process', re: /child_process|exec\s*\(|spawn\s*\(/g, chain: 'PP → RCE' },
  { name: 'vm.runInThisContext', re: /vm\.runInThisContext|vm\.Script/g, chain: 'PP → Sandbox Escape' },
];

const findings = [];

for (const pat of PP_PATTERNS) {
  pat.re.lastIndex = 0;
  let m;
  while ((m = pat.re.exec(code)) !== null) {
    const line = code.substring(0, m.index).split('\n').length;
    const ctx = code.substring(Math.max(0, m.index - 60), Math.min(code.length, m.index + 60)).replace(/\n/g, ' ').substring(0, 120);
    findings.push({ type: pat.name, severity: pat.severity, line, context: ctx, note: pat.note });
  }
}

const nearbySinks = [];
for (const f of findings) {
  for (const sink of SINKS_AFTER_PP) {
    sink.re.lastIndex = 0;
    const afterCode = code.substring(code.indexOf('\n', code.indexOf('\n', code.indexOf('\n', code.indexOf('\n', f.line) + 1) + 1) + 1));
    if (sink.re.test(afterCode)) {
      nearbySinks.push({ ppType: f.type, ppLine: f.line, sink: sink.name, chain: sink.chain });
    }
  }
}

console.log(`\n========================================`);
console.log(`  Prototype Pollution Gadget Finder`);
console.log(`========================================`);
console.log(`  Total patterns:  ${findings.length}`);
console.log(`  Nearby sinks:    ${nearbySinks.length}`);
console.log('');

if (findings.length === 0) {
  console.log('  No prototype pollution patterns detected.\n');
  process.exit(0);
}

const bySev = {};
for (const f of findings) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
console.log('  By severity:');
Object.entries(bySev).sort((a, b) => a[0] === 'CRITICAL' ? -1 : 0).forEach(([s, c]) => {
  console.log(`    ${harden.colorize(s)}: ${c}`);
});
console.log('');

const grouped = {};
for (const f of findings) {
  if (!grouped[f.type]) grouped[f.type] = [];
  grouped[f.type].push(f);
}
console.log('  By pattern:');
Object.entries(grouped).sort((a, b) => b[1].length - a[1].length).forEach(([type, items]) => {
  console.log(`    ${type.padEnd(35)}: ${items.length}`);
  items.slice(0, 2).forEach(f => console.log(`      Ln ${f.line} — ${f.context.substring(0, 80)}`));
});
console.log('');

if (nearbySinks.length > 0) {
  console.log('  Possible attack chains (PP + nearby sink):');
  for (const ns of nearbySinks.slice(0, 10)) {
    console.log(`    ${ns.chain}: "${ns.ppType}" @ line ${ns.ppLine} → "${ns.sink}"`);
  }
  console.log('');
}

module.exports = { PP_PATTERNS, SINKS_AFTER_PP };
