const fs = require('fs');
const path = require('path');

const FP_RULES_PATH = path.join(__dirname, '..', 'config', 'fp-rules.json');

function loadFPRules() {
  try {
    if (fs.existsSync(FP_RULES_PATH)) return JSON.parse(fs.readFileSync(FP_RULES_PATH, 'utf-8'));
  } catch {}
  return { rules: [], stats: { totalFPs: 0, learned: 0 } };
}

function saveFPRules(rules) {
  fs.mkdirSync(path.dirname(FP_RULES_PATH), { recursive: true });
  fs.writeFileSync(FP_RULES_PATH, JSON.stringify(rules, null, 2));
}

function learnFP(finding) {
  const db = loadFPRules();
  const pattern = {
    pattern: finding.value || finding.match,
    filePattern: finding.file ? path.basename(finding.file).replace(/[0-9]/g, '#') : null,
    context: (finding.context || '').substring(0, 60),
    variableName: finding.variableName || null,
    count: 1,
    added: new Date().toISOString()
  };

  const existing = db.rules.find(r =>
    r.pattern === pattern.pattern ||
    (r.context && pattern.context && r.context === pattern.context)
  );

  if (existing) {
    existing.count++;
    existing.lastSeen = new Date().toISOString();
  } else {
    db.rules.push(pattern);
    db.stats.learned++;
  }
  db.stats.totalFPs++;
  saveFPRules(db);
  return { matched: existing ? true : false, rule: pattern };
}

function isFP(finding, filePath) {
  const db = loadFPRules();
  const fileName = filePath ? path.basename(filePath).replace(/[0-9]/g, '#') : null;
  const value = finding.value || finding.match || '';
  const ctx = (finding.context || '').substring(0, 60);

  for (const rule of db.rules) {
    if (rule.pattern === value) return { isFP: true, rule, reason: 'Exact match' };
    if (rule.context && ctx && rule.context === ctx) return { isFP: true, rule, reason: 'Context match' };
    if (rule.filePattern && fileName && rule.filePattern === fileName && value.length > 10) {
      return { isFP: true, rule, reason: 'File pattern match' };
    }
  }
  return { isFP: false };
}

function getFPRules() { return loadFPRules(); }

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    const rules = loadFPRules();
    console.log(`\nFP Learner — ${rules.stats.totalFPs} total, ${rules.rules.length} unique rules`);
    rules.rules.slice(0, 20).forEach(r => console.log(`  ${r.pattern.substring(0, 60)} (x${r.count})`));
    if (rules.rules.length > 20) console.log(`  ... and ${rules.rules.length - 20} more`);
    console.log('');
    process.exit(0);
  }
  if (args[0] === '--learn' && args[1]) {
    const finding = JSON.parse(args[1]);
    const result = learnFP(finding);
    console.log(JSON.stringify(result));
  }
  if (args[0] === '--check' && args[1]) {
    const finding = JSON.parse(args[1]);
    const filePath = args[2] || null;
    console.log(JSON.stringify(isFP(finding, filePath)));
  }
  if (args[0] === '--confirm' && args[1]) {
    const db = loadFPRules();
    const rule = db.rules.find(r => r.pattern === args[1]);
    if (rule) {
      rule.confirmed = (rule.confirmed || 0) + 1;
      rule.lastConfirmed = new Date().toISOString();
      saveFPRules(db);
      console.log(JSON.stringify({ confirmed: true, count: rule.confirmed }));
    } else {
      console.log(JSON.stringify({ confirmed: false, error: 'Rule not found' }));
    }
  }
}

module.exports = { learnFP, isFP, loadFPRules, getFPRules };
