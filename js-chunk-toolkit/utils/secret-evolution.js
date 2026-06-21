const fs = require('fs');
const path = require('path');

function loadHistory(historyPath) {
  try {
    if (!fs.existsSync(historyPath)) return { version: 1, scans: [] };
    return JSON.parse(fs.readFileSync(historyPath, 'utf-8'));
  } catch { return { version: 1, scans: [] }; }
}

function saveHistory(historyPath, history) {
  const dir = path.dirname(historyPath);
  if (dir) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(historyPath, JSON.stringify(history, null, 2));
}

function fingerprintSecret(value) {
  const clean = value.replace(/[0-9]/g, '0').replace(/[a-f]/g, 'f').replace(/[g-z]/g, 'x').replace(/[A-F]/g, 'F').replace(/[G-Z]/g, 'X');
  const prefix = value.substring(0, Math.min(12, value.length));
  return `${clean.substring(0, 20)}-${prefix}`;
}

function classifySecret(value) {
  if (/^gh[pousr]_/.test(value)) return 'github_token';
  if (/^AKIA/.test(value)) return 'aws_key';
  if (/^eyJ/.test(value)) return 'jwt';
  if (/^sk-/.test(value) && value.length > 20) return 'openai_key';
  if (/^xox[baprs]-/.test(value)) return 'slack_token';
  if (/^pk_live_|^sk_live_|^pk_test_|^sk_test_/.test(value)) return 'stripe_key';
  if (/^AC[a-z0-9]{32}$/.test(value)) return 'twilio_sid';
  return 'unknown_secret';
}

function analyzeEvolution(historyPath, currentFindings, scanLabel) {
  const history = loadHistory(historyPath);
  const now = new Date().toISOString();
  const currentFingerprints = new Set();

  for (const f of currentFindings) {
    const fp = fingerprintSecret(f.code);
    currentFingerprints.add(fp);
    const existing = history.scans.find(s => s.fingerprint === fp);
    if (existing) {
      existing.lastSeen = now;
      existing.seenCount++;
      existing.lastValue = f.code.substring(0, 60);
      existing.lines = existing.lines || [];
      if (!existing.lines.includes(f.line)) existing.lines.push(f.line);
    } else {
      history.scans.push({
        fingerprint: fp,
        type: classifySecret(f.code),
        firstSeen: now,
        lastSeen: now,
        seenCount: 1,
        firstValue: f.code.substring(0, 60),
        lastValue: f.code.substring(0, 60),
        lines: [f.line],
        scanLabel,
        severity: f.severity,
        file: f.file
      });
    }
  }

  const results = {
    totalSecrets: history.scans.length,
    newThisScan: 0,
    rotated: [],
    stable: 0,
    typeBreakdown: {},
  };

  for (const s of history.scans) {
    if (!results.typeBreakdown[s.type]) results.typeBreakdown[s.type] = 0;
    results.typeBreakdown[s.type]++;

    if (s.seenCount === 1 && s.scanLabel === scanLabel) {
      results.newThisScan++;
    } else if (s.seenCount > 1 && s.scanLabel !== scanLabel) {
      if (s.firstValue !== s.lastValue) {
        results.rotated.push({ type: s.type, first: s.firstValue, last: s.lastValue, changes: s.seenCount });
      } else {
        results.stable++;
      }
    }
  }

  history.lastScan = now;

  const newSecrets = history.scans.filter(s => s.seenCount === 1 && s.scanLabel === scanLabel);
  const rotatedSecrets = history.scans.filter(s => s.firstValue !== s.lastValue && s.seenCount > 1);

  return { results, newSecrets: newSecrets.slice(0, 20), rotatedSecrets: rotatedSecrets.slice(0, 10), history };
}

function generateReport(evolutionResult) {
  const { results, newSecrets, rotatedSecrets } = evolutionResult;

  console.log(`\n========================================`);
  console.log(`  Secret Evolution Report`);
  console.log(`========================================`);
  console.log(`  Total tracked secrets:  ${results.totalSecrets}`);
  console.log(`  New this scan:          ${results.newThisScan}`);
  console.log(`  Rotated/changed:        ${results.rotated.length}`);
  console.log(`  Stable across scans:    ${results.stable}`);
  console.log('');

  if (Object.keys(results.typeBreakdown).length > 0) {
    console.log('  By type:');
    for (const [type, count] of Object.entries(results.typeBreakdown).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${type.padEnd(20)}: ${count}`);
    }
    console.log('');
  }

  if (newSecrets.length > 0) {
    console.log('  New secrets discovered:');
    newSecrets.slice(0, 10).forEach(s => {
      console.log(`    ${s.type.padEnd(20)}: ${s.firstValue.substring(0, 50)}`);
    });
    console.log('');
  }

  if (rotatedSecrets.length > 0) {
    console.log('  [!] Rotated/changed secrets (possible credential rotation):');
    rotatedSecrets.slice(0, 5).forEach(s => {
      console.log(`    ${s.type.padEnd(20)}: ${s.firstValue.substring(0, 30)} → ${s.lastValue.substring(0, 30)}`);
    });
    console.log('');
  }
}

module.exports = { analyzeEvolution, generateReport, fingerprintSecret, classifySecret };
