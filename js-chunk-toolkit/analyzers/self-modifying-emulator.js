const fs = require('fs');
const path = require('path');
const vm = require('vm');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node self-modifying-emulator.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

function emulateSelfModifying(inputCode) {
  const results = { evalStrings: 0, resolved: [], failed: [], total: 0 };

  const evalRe = /eval\s*\(\s*["'`]([^"'`]{10,})["'`]\s*\)/g;
  let m;
  while ((m = evalRe.exec(inputCode)) !== null) {
    results.total++;
    try {
      const script = new vm.Script(m[1], { timeout: 200 });
      const result = script.runInNewContext({}, { timeout: 200 });
      if (result !== undefined && typeof result === 'string') {
        results.resolved.push({ type: 'eval', input: m[1].substring(0, 80), output: result.substring(0, 200) });
      }
    } catch (e) {
      results.failed.push({ type: 'eval', input: m[1].substring(0, 80), error: e.message });
    }
  }

  const funcRe = /new\s+Function\s*\(\s*["'`]([^"'`]{10,})["'`]\s*\)/g;
  while ((m = funcRe.exec(inputCode)) !== null) {
    results.total++;
    try {
      const fn = new Function(m[1]);
      const result = fn();
      if (result !== undefined) {
        results.resolved.push({ type: 'Function()', input: m[1].substring(0, 80), output: String(result).substring(0, 200) });
      }
    } catch (e) {
      results.failed.push({ type: 'Function()', input: m[1].substring(0, 80), error: e.message });
    }
  }

  const timeoutRe = /setTimeout\s*\(\s*["'`]([^"'`]{20,})["'`]/g;
  while ((m = timeoutRe.exec(inputCode)) !== null) {
    results.total++;
    try {
      const script = new vm.Script(m[1], { timeout: 200 });
      const result = script.runInNewContext({}, { timeout: 200 });
      if (result !== undefined) {
        results.resolved.push({ type: 'setTimeout', input: m[1].substring(0, 80), output: String(result).substring(0, 200) });
      }
    } catch (e) {
      results.failed.push({ type: 'setTimeout', input: m[1].substring(0, 80), error: e.message });
    }
  }

  const binRe = /atob\s*\(\s*["'`]([^"'`]{10,})["'`]\s*\)/g;
  while ((m = binRe.exec(inputCode)) !== null) {
    results.total++;
    try {
      const decoded = Buffer.from(m[1], 'base64').toString('utf-8');
      if (decoded.length > 3) {
        results.resolved.push({ type: 'atob', input: m[1].substring(0, 40), output: decoded.substring(0, 200) });
      }
    } catch (e) {}
  }

  const fccRe = /String\.fromCharCode\s*\(([^)]+)\)/g;
  while ((m = fccRe.exec(inputCode)) !== null) {
    results.total++;
    try {
      const nums = m[1].split(',').map(Number);
      const decoded = String.fromCharCode(...nums);
      if (decoded.length > 3) {
        results.resolved.push({ type: 'fromCharCode', input: m[1].substring(0, 40), output: decoded.substring(0, 200) });
      }
    } catch (e) {}
  }

  return results;
}

if (isCLI) {
  const result = emulateSelfModifying(code);
  console.log(`\n========================================`);
  console.log(`  Self-Modifying Code Emulation`);
  console.log(`========================================`);
  console.log(`  Attempted: ${result.total}`);
  console.log(`  Resolved:  ${result.resolved.length}`);
  console.log(`  Failed:    ${result.failed.length}`);
  if (result.resolved.length > 0) {
    console.log('\n  Resolved:');
    result.resolved.slice(0, 15).forEach(r => console.log(`    [${r.type}] ${r.input.substring(0, 60)} → ${r.output.substring(0, 100)}`));
  }
  if (result.failed.length > 0) {
    console.log('\n  Failed:');
    result.failed.slice(0, 5).forEach(f => console.log(`    [${f.type}] ${f.input.substring(0, 60)}: ${f.error}`));
  }
  console.log('');
}

module.exports = { emulateSelfModifying };
