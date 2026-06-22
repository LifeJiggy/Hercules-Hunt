const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function correlateSecret(value, context = '') {
  const result = { severity: 'MEDIUM', signals: [], score: 0, type: 'unknown' };

  const patterns = [
    { type: 'AWS Key', re: /AKIA[0-9A-Z]{16}/, severity: 'CRITICAL', signal: 10 },
    { type: 'AWS Secret', re: /[A-Za-z0-9\/+]{40}/, severity: 'CRITICAL', signal: 9, contextCheck: (c) => /aws|secret|access/i.test(c) },
    { type: 'GitHub PAT', re: /ghp_[A-Za-z0-9]{36}/, severity: 'CRITICAL', signal: 10 },
    { type: 'GitHub Old', re: /[A-Fa-f0-9]{40}/, severity: 'HIGH', signal: 6, contextCheck: (c) => /github|token|pat/i.test(c) },
    { type: 'OpenAI Key', re: /sk-[A-Za-z0-9]{20,}/, severity: 'CRITICAL', signal: 10 },
    { type: 'Stripe Live', re: /sk_live_[A-Za-z0-9]{24,}/, severity: 'CRITICAL', signal: 10 },
    { type: 'Stripe Test', re: /sk_test_[A-Za-z0-9]{24,}/, severity: 'LOW', signal: 2 },
    { type: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'MEDIUM', signal: 5 },
    { type: 'Private Key PEM', re: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'CRITICAL', signal: 10 },
    { type: 'Slack Token', re: /xox[baprs]-[A-Za-z0-9]{10,}/, severity: 'HIGH', signal: 8 },
    { type: 'Google API Key', re: /AIza[0-9A-Za-z_-]{35}/, severity: 'HIGH', signal: 7 },
    { type: 'Heroku API Key', re: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/, severity: 'HIGH', signal: 7 },
    { type: 'MongoDB URI', re: /mongodb(?:\+srv)?:\/\/[^\s"'`]+/, severity: 'HIGH', signal: 8 },
    { type: 'PostgreSQL URI', re: /postgres(?:ql)?:\/\/[^\s"'`]+/, severity: 'HIGH', signal: 8 },
    { type: 'MySQL URI', re: /mysql:\/\/[^\s"'`]+/, severity: 'HIGH', signal: 7 },
    { type: 'Redis URI', re: /redis:\/\/[^\s"'`]+/, severity: 'MEDIUM', signal: 5 },
    { type: 'SendGrid Key', re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, severity: 'HIGH', signal: 8 },
    { type: 'Twilio SID', re: /AC[A-Za-z0-9]{32}/, severity: 'HIGH', signal: 7 },
    { type: 'Docker Hub', re: /dockerhub|DOCKER_HUB/i, severity: 'MEDIUM', signal: 4 },
    { type: 'npm token', re: /npm_[A-Za-z0-9]{36}/, severity: 'HIGH', signal: 7 },
    { type: 'PyPI token', re: /pypi[A-Za-z0-9_-]{36,}/i, severity: 'HIGH', signal: 7 },
    { type: 'Slack Webhook', re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]{44}/, severity: 'HIGH', signal: 8 },
    { type: 'Discord Webhook', re: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{68}/, severity: 'HIGH', signal: 8 },
    { type: 'Generic high-entropy', re: /^[A-Za-z0-9_-]{32,}$/, severity: 'MEDIUM', signal: 3 },
  ];

  for (const p of patterns) {
    p.re.lastIndex = 0;
    const m = p.re.exec(value);
    if (m) {
      let matched = true;
      if (p.contextCheck && !p.contextCheck(context)) matched = false;
      if (matched) {
        result.signals.push(p.type);
        result.score += p.signal;
        result.severity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].find(s => s === p.severity) || result.severity;
      }
    }
  }

  if (result.score >= 20) result.severity = 'CRITICAL';
  else if (result.score >= 10) result.severity = 'HIGH';
  else if (result.score >= 5) result.severity = 'MEDIUM';
  else result.severity = 'LOW';

  return result;
}

const BREACH_DB_PATH = path.join(__dirname, '..', 'config', 'known-breaches.json');

function loadBreachDB() {
  try {
    if (fs.existsSync(BREACH_DB_PATH)) return JSON.parse(fs.readFileSync(BREACH_DB_PATH, 'utf-8'));
  } catch {}
  return { breaches: [] };
}

function checkBreachDatabase(value) {
  const db = loadBreachDB();
  for (const breach of db.breaches) {
    if (breach.pattern && new RegExp(breach.pattern).test(value)) {
      return { breached: true, source: breach.source, date: breach.date, description: breach.description };
    }
  }
  return { breached: false };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: node credential-correlator.js <value> [context]');
    process.exit(0);
  }
  const value = args[0];
  const context = args[1] || '';
  const correlation = correlateSecret(value, context);
  console.log(`\n========================================`);
  console.log(`  Credential Correlation`);
  console.log(`========================================`);
  console.log(`  Value: ${value.substring(0, 60)}...`);
  console.log(`  Type:  ${correlation.type}`);
  console.log(`  Score: ${correlation.score}`);
  console.log(`  Severity: ${correlation.severity}`);
  if (correlation.signals.length > 0) {
    console.log('  Matched patterns:');
    correlation.signals.forEach(s => console.log(`    - ${s}`));
  }
  const breach = checkBreachDatabase(value);
  if (breach.breached) console.log(`  [!] Known breach: ${breach.source} (${breach.date})`);
  console.log('');
}

module.exports = { correlateSecret, checkBreachDatabase };
