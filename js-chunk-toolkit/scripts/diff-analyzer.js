const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length < 2) {
  console.log('Usage: node diff-analyzer.js <before.json> <after.json>');
  console.log('  Compares two scan outputs and reports delta.');
  process.exit(1);
}

function loadReport(filePath) {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
  const findings = [];
  if (data.findings) findings.push(...data.findings);
  if (data.secrets) findings.push(...data.secrets);
  if (data.modules) findings.push(...data.modules.map(m => ({ id: m.id, name: m.name, type: 'module' })));
  if (data.topComplex) findings.push(...data.topComplex.map(f => ({ id: f.name, name: f.name, type: 'function', complexity: f.complexity })));
  return { data, findings, file: filePath };
}

const before = loadReport(args[0]);
const after = loadReport(args[1]);

const beforeIds = new Set(before.findings.map(f => f.id || f.name || f.pattern));
const afterIds = new Set(after.findings.map(f => f.id || f.name || f.pattern));

const added = after.findings.filter(f => !beforeIds.has(f.id || f.name || f.pattern));
const removed = before.findings.filter(f => !afterIds.has(f.id || f.name || f.pattern));
const common = after.findings.filter(f => beforeIds.has(f.id || f.name || f.pattern));

console.log(`\n========================================`);
console.log(`  Differential Analysis`);
console.log(`========================================`);
console.log(`  Before: ${path.basename(args[0])} (${before.findings.length} items)`);
console.log(`  After:  ${path.basename(args[1])} (${after.findings.length} items)`);
console.log(`  Added:   ${added.length}`);
console.log(`  Removed: ${removed.length}`);
console.log(`  Common:  ${common.length}`);

if (added.length > 0) {
  console.log('\n  New findings:');
  added.slice(0, 20).forEach(f => {
    const label = f.name || f.pattern || f.value || f.id;
    const sev = f.severity || f.type || '';
    console.log(`    [${sev}] ${String(label).substring(0, 80)}`);
  });
  if (added.length > 20) console.log(`    ... and ${added.length - 20} more`);
}

if (removed.length > 0) {
  console.log(`\n  Removed findings: ${removed.length}`);
  removed.slice(0, 10).forEach(f => {
    const label = f.name || f.pattern || f.value || f.id;
    console.log(`    ${String(label).substring(0, 80)}`);
  });
}

const severityChanges = [];
for (const bf of before.findings) {
  const af = after.findings.find(f => (f.id || f.name) === (bf.id || bf.name));
  if (af && af.severity !== bf.severity) {
    severityChanges.push({ name: bf.name || bf.pattern, from: bf.severity, to: af.severity });
  }
}
if (severityChanges.length > 0) {
  console.log('\n  Severity changes:');
  severityChanges.slice(0, 10).forEach(s => console.log(`    ${s.name}: ${s.from} → ${s.to}`));
}
console.log('');
