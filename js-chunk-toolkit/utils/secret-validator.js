const path = require('path');

const CONTEXT_RADIUS = 200;

const DOWNRANK_PATTERNS = [
  /test|mock|stub|fake|sample|example|placeholder|dummy/i,
  /TODO|FIXME|HACK|XXX|WORKAROUND/i,
  /localhost|127\.0\.0\.1|0\.0\.0\.0/i,
  /^test_|^sk_test_|^pk_test_|^test-|test\.|\.test/i,
  /console\.(log|debug|warn)\s*\(/,
  /\/\/.*TODO|\/\/.*FIXME|\/\/.*HACK/,
  /if\s*\(\s*(false|0|null|undefined)\s*\)/,
  /['"]test['"]\s*[:=]\s*['"]/,
];

const UPRANK_PATTERNS = [
  /production|prod|live|release|deploy|build/i,
  /secret|private|credential|password|token|key|auth/i,
  /api[._]?key|api[._]?secret|client[._]?secret/i,
  /process\.env\.|import\.meta\.env\./i,
  /require\(['"](?:\.\/)?config|\.\/env|\.\/credentials/i,
  /export|module\.exports/i,
  /docker|kube|kubernetes|helm|terraform|cloudformation/i,
  /\.pem|\.key|\.crt|\.cert|keystore|truststore/i,
];

const FP_SIGNALS = [
  { re: /isProduction|isDev|__DEV__|NODE_ENV/, type: 'env_conditional', weight: -30 },
  { re: /typeof \w+ === 'undefined'/, type: 'typeof_check', weight: -10 },
  { re: /\/\/ @ts-ignore|\/\/ eslint-disable/, type: 'lint_annotation', weight: -5 },
  { re: /\.slice\(|\.substring\(|\.replace\(/, type: 'string_manipulation', weight: -10 },
  { re: /\/\/\s*(?:TODO|HACK|FIXME)/, type: 'todo_comment', weight: -20 },
  { re: /require\.main|module\.hot/, type: 'module_runtime', weight: -15 },
  { re: /node_modules/, type: 'dependency', weight: -25 },
  { re: /\b(?:post|get|put|delete|patch|options)\s*\(/, type: 'http_client', weight: -5 },
  { re: /\.test\(|\.match\(/, type: 'regex_test', weight: -10 },
  { re: /import\s*\{[^}]*\}\s*from/, type: 'import_statement', weight: -5 },
  { re: /`\$\{[^}]*\}`/, type: 'template_literal', weight: 5 },
];

function getContextLines(content, index, radius = CONTEXT_RADIUS) {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  return content.substring(start, end);
}

function validateSecretContext(content, index, value) {
  const ctx = getContextLines(content, index);
  let score = 50;
  let signals = [];

  for (const p of DOWNRANK_PATTERNS) {
    if (p.test(ctx)) { score -= 20; signals.push(`downrank:${p.source.substring(0, 30)}`); }
  }

  for (const p of UPRANK_PATTERNS) {
    if (p.test(ctx)) { score += 20; signals.push(`uprank:${p.source.substring(0, 30)}`); }
  }

  for (const sig of FP_SIGNALS) {
    if (sig.re.test(ctx)) {
      score += sig.weight;
      signals.push(`${sig.type}:${sig.weight}`);
    }
  }

  const entropy = hardenShannon(value);
  if (entropy > 4.5) score += 15;
  else if (entropy < 2.5) score -= 10;

  if (/^gh[pousr]_/.test(value)) score += 25;
  if (/^AKIA/.test(value)) score += 25;
  if (value.startsWith('sk-') && value.length > 30) score += 25;
  if (/^eyJ/.test(value)) score += 20;
  if (/^xox[baprs]-/.test(value)) score += 20;

  return {
    score: Math.max(0, Math.min(100, score)),
    confidence: score >= 70 ? 'HIGH' : score >= 45 ? 'MEDIUM' : 'LOW',
    signals: signals.slice(0, 10),
    entropy: Math.round(entropy * 100) / 100
  };
}

function hardenShannon(str) {
  if (!str || str.length < 8) return 0;
  const freq = {};
  for (const ch of str) { freq[ch] = (freq[ch] || 0) + 1; }
  let e = 0;
  for (const count of Object.values(freq)) {
    const p = count / str.length;
    if (p > 0) e -= p * Math.log2(p);
  }
  return e;
}

module.exports = { validateSecretContext, getContextLines, CONTEXT_RADIUS, DOWNRANK_PATTERNS, UPRANK_PATTERNS, FP_SIGNALS };
