const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'output', 'scan-history.jsonl');
const SUMMARY_PATH = path.join(__dirname, '..', 'output', 'scan-summary.json');

function ensureDir(filePath) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
}

function recordScan(target, findings) {
  ensureDir(DB_PATH);
  const entry = {
    timestamp: new Date().toISOString(),
    target,
    totalFindings: findings.length,
    bySeverity: {},
    topFindings: findings.slice(0, 5).map(f => ({
      value: (f.value || f.pattern || f.name || '').substring(0, 60),
      severity: f.severity || f.type || 'info'
    }))
  };
  for (const f of findings) {
    const sev = f.severity || f.type || 'info';
    entry.bySeverity[sev] = (entry.bySeverity[sev] || 0) + 1;
  }
  fs.appendFileSync(DB_PATH, JSON.stringify(entry) + '\n');
  return entry;
}

function getHistory(target, limit = 50) {
  const results = [];
  try {
    if (!fs.existsSync(DB_PATH)) return results;
    const lines = fs.readFileSync(DB_PATH, 'utf-8').split('\n').filter(Boolean);
    for (const line of lines.slice(-limit)) {
      try {
        const entry = JSON.parse(line);
        if (!target || entry.target === target) results.push(entry);
      } catch {}
    }
  } catch {}
  return results;
}

function generateSummary() {
  const history = getHistory(null, 500);
  const summary = {
    totalScans: history.length,
    uniqueTargets: new Set(history.map(h => h.target)).size,
    totalFindings: history.reduce((s, h) => s + h.totalFindings, 0),
    lastScan: history.length > 0 ? history[history.length - 1].timestamp : null,
    severityTrend: {}
  };

  for (const entry of history) {
    for (const [sev, count] of Object.entries(entry.bySeverity)) {
      if (!summary.severityTrend[sev]) summary.severityTrend[sev] = [];
      summary.severityTrend[sev].push({ date: entry.timestamp, count });
    }
  }

  ensureDir(SUMMARY_PATH);
  fs.writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2));
  return summary;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    const summary = generateSummary();
    console.log(`\n========================================`);
    console.log(`  Scan History Database`);
    console.log(`========================================`);
    console.log(`  Total scans:  ${summary.totalScans}`);
    console.log(`  Targets:      ${summary.uniqueTargets}`);
    console.log(`  Findings:     ${summary.totalFindings}`);
    console.log(`  Last scan:    ${summary.lastScan || 'never'}`);
    if (Object.keys(summary.severityTrend).length > 0) {
      console.log('\n  Severity trend:');
      for (const [sev, points] of Object.entries(summary.severityTrend)) {
        const latest = points[points.length - 1];
        console.log(`    ${sev}: ${latest ? latest.count : 0} (latest)`);
      }
    }
    console.log(`\n  History file: ${DB_PATH}`);
    console.log('');
    process.exit(0);
  }

  if (args[0] === '--record' && args[1]) {
    const findings = args[2] ? JSON.parse(args[2]) : [];
    const entry = recordScan(args[1], findings);
    console.log(JSON.stringify(entry));
  }

  if (args[0] === '--history') {
    const target = args[1] || null;
    const history = getHistory(target);
    console.log(JSON.stringify(history));
  }
}

module.exports = { recordScan, getHistory, generateSummary };
