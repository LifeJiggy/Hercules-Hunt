const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node side-effect-analyzer.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

const IMPURE_PATTERNS = [
  { name: 'DOM write', re: /\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(/g },
  { name: 'Network call', re: /fetch\s*\(|XMLHttpRequest|\.open\s*\(|WebSocket\s*\(/g },
  { name: 'Cookie access', re: /document\.cookie/g },
  { name: 'localStorage', re: /localStorage\./g },
  { name: 'sessionStorage', re: /sessionStorage\./g },
  { name: 'eval/Function', re: /\beval\s*\(|new\s+Function\s*\(/g },
  { name: 'console/log', re: /console\.(log|warn|error|info|debug)\s*\(/g },
  { name: 'Date.now() / Math.random', re: /Date\.now\s*\(|Math\.random\s*\(/g },
  { name: 'setTimeout/Interval', re: /setTimeout\s*\(|setInterval\s*\(/g },
  { name: 'window.location', re: /window\.location|location\.href\s*=/g },
  { name: 'alert/confirm/prompt', re: /alert\s*\(|confirm\s*\(|prompt\s*\(/g },
  { name: 'process.env/argv/exit', re: /process\.(env|argv|exit|cwd|chdir)\s*\(?/g },
  { name: 'fs module', re: /fs\.(readFile|writeFile|unlink|mkdir|rmdir|exists)\s*\(/g },
];

function analyzeSideEffects(inputCode) {
  const functions = [];
  const funcRe = /(?:function\s+(\w+)\s*\(|(\w+)\s*=\s*function\s*\()/g;
  let fm;
  while ((fm = funcRe.exec(inputCode)) !== null) {
    const name = fm[1] || fm[2];
    const start = fm.index;
    const end = inputCode.indexOf('function', start + 1);
    const body = inputCode.substring(start, end > start ? end : start + 1000);
    const effects = [];
    for (const p of IMPURE_PATTERNS) {
      p.re.lastIndex = 0;
      let m;
      while ((m = p.re.exec(body)) !== null) effects.push(p.name);
    }
    functions.push({ name, impure: effects.length > 0, effectCount: effects.length, effects: [...new Set(effects)] });
  }

  const pure = functions.filter(f => !f.impure);
  const impure = functions.filter(f => f.impure);
  return { functions, pure, impure };
}

if (isCLI) {
  const result = analyzeSideEffects(code);
  console.log(`\n========================================`);
  console.log(`  Side-Effect Analysis`);
  console.log(`========================================`);
  console.log(`  Functions:      ${result.functions.length}`);
  console.log(`  Pure:           ${result.pure.length}`);
  console.log(`  Impure:         ${result.impure.length}`);
  if (result.impure.length > 0) {
    console.log('\n  Impure functions:');
    result.impure.slice(0, 20).forEach(f => console.log(`    ${f.name} (${f.effects.slice(0, 4).join(', ')})`));
  }
  if (result.pure.length > 0) {
    console.log('\n  Pure functions (safe to deobfuscate):');
    result.pure.slice(0, 10).forEach(f => console.log(`    ${f.name}`));
  }
  console.log('');
}

module.exports = { analyzeSideEffects, IMPURE_PATTERNS };
