const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node deduplicator.js <findings.json> [--output deduped.json]');
  console.log('  findings.json: array of finding objects with {category, name, file, line, code, severity, cvss, hash?}');
  process.exit(1);
}

const inputPath = args[0];
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : null;

const findings = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
const arrayInput = Array.isArray(findings) ? findings : (findings.findings || []);

function normalizeCode(code) {
  if (!code) return '';
  return code.replace(/\s+/g, ' ').trim().substring(0, 200);
}

function computeFingerprint(f) {
  const file = (f.file || f.filePath || '').replace(/\\/g, '/');
  const line = f.line || 0;
  const code = normalizeCode(f.code || '');
  const cat = f.category || '';
  const name = f.name || '';
  const raw = `${file}:${line}:${cat}:${name}:${code}`;
  return crypto.createHash('md5').update(raw).digest('hex');
}

function computeCloseFingerprint(f) {
  const file = (f.file || f.filePath || '').replace(/\\/g, '/');
  const cat = f.category || '';
  const name = f.name || '';
  const code = normalizeCode(f.code || '').substring(0, 80);
  const raw = `${file}:${cat}:${name}:${code}`;
  return crypto.createHash('md5').update(raw).digest('hex');
}

const EXACT_DUP_GROUPS = {};
const CLOSE_DUP_GROUPS = {};

findings.forEach(f => {
  const fp = computeFingerprint(f);
  if (!EXACT_DUP_GROUPS[fp]) EXACT_DUP_GROUPS[fp] = [];
  EXACT_DUP_GROUPS[fp].push(f);
});

findings.forEach(f => {
  const fp = computeCloseFingerprint(f);
  if (!CLOSE_DUP_GROUPS[fp]) CLOSE_DUP_GROUPS[fp] = [];
  CLOSE_DUP_GROUPS[fp].push(f);
});

const keptFindings = [];
const removedCount = { exact: 0, close: 0 };

Object.values(EXACT_DUP_GROUPS).forEach(group => {
  if (group.length === 1) {
    keptFindings.push(group[0]);
    return;
  }
  const best = group.reduce((a, b) => {
    const aScore = (a.cvss || 0) + (a.severity === 'CRITICAL' ? 10 : a.severity === 'HIGH' ? 7 : a.severity === 'MEDIUM' ? 5 : 2);
    const bScore = (b.cvss || 0) + (b.severity === 'CRITICAL' ? 10 : b.severity === 'HIGH' ? 7 : b.severity === 'MEDIUM' ? 5 : 2);
    return aScore >= bScore ? a : b;
  });
  best._duplicateCount = group.length;
  best._dedupInfo = `Exact duplicate: ${group.length - 1} other identical findings merged`;
  keptFindings.push(best);
  removedCount.exact += group.length - 1;
});

const closeKept = [];
const processedCloseFps = new Set();

keptFindings.forEach(f => {
  const fp = computeCloseFingerprint(f);
  if (processedCloseFps.has(fp)) return;
  processedCloseFps.add(fp);
  const group = CLOSE_DUP_GROUPS[fp] || [];
  if (group.length <= 1) {
    closeKept.push(f);
    return;
  }
  const best = group.reduce((a, b) => {
    const aScore = (a.cvss || 0) + (a.severity === 'CRITICAL' ? 10 : a.severity === 'HIGH' ? 7 : a.severity === 'MEDIUM' ? 5 : 2);
    const bScore = (b.cvss || 0) + (b.severity === 'CRITICAL' ? 10 : b.severity === 'HIGH' ? 7 : b.severity === 'MEDIUM' ? 5 : 2);
    return aScore >= bScore ? a : b;
  });
  const exactInGroup = EXACT_DUP_GROUPS[computeFingerprint(f)] || [];
  const totalClose = group.length;
  const alreadyExactMerged = exactInGroup.length > 1;
  const extraRemoved = alreadyExactMerged ? 0 : totalClose - 1;
  best._closeDuplicateCount = totalClose;
  best._dedupInfo = (best._dedupInfo || '') + `; Close match: ${extraRemoved} similar findings merged (same file/category/code)` + '';
  closeKept.push(best);
  removedCount.close += extraRemoved;
});

const stats = {
  input: arrayInput.length,
  exactDuplicates: removedCount.exact,
  closeDuplicates: removedCount.close,
  output: closeKept.length,
  reduction: arrayInput.length > 0 ? Math.round((1 - closeKept.length / arrayInput.length) * 100) + '%' : '0%'
};

const result = {
  metadata: {
    deduplicationDate: new Date().toISOString(),
    inputCount: arrayInput.length,
    outputCount: closeKept.length,
    exactDuplicatesRemoved: removedCount.exact,
    closeDuplicatesRemoved: removedCount.close,
    totalReduction: stats.reduction
  },
  findings: closeKept,
  deduplicationLog: {
    groups: Object.keys(EXACT_DUP_GROUPS).filter(k => EXACT_DUP_GROUPS[k].length > 1).length,
    closeGroups: Object.keys(CLOSE_DUP_GROUPS).filter(k => CLOSE_DUP_GROUPS[k].length > 1).length
  }
};

console.log('');
console.log('========================================');
console.log('  Deduplicator Results');
console.log('========================================');
console.log(`  Input findings:     ${stats.input}`);
console.log(`  Exact duplicates:   ${stats.exactDuplicates}`);
console.log(`  Near duplicates:    ${stats.closeDuplicates}`);
console.log(`  Output findings:    ${stats.output}`);
console.log(`  Reduction:          ${stats.reduction}`);
console.log('');

if (outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log(`[OK] Deduplicated output written to ${outputPath}`);
} else {
  console.log(JSON.stringify(result, null, 2));
}
