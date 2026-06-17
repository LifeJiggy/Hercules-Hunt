const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node false-positive-filter.js <findings.json> [--rules fp-rules.json] [--output filtered.json]');
  process.exit(1);
}

const inputPath = args[0];
const rulesFlag = args.indexOf('--rules');
const rulesPath = rulesFlag > -1 && args[rulesFlag + 1] ? args[rulesFlag + 1] : path.join(__dirname, '..', 'config', 'false-positive-rules.json');
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : null;

const findings = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
const arrayInput = Array.isArray(findings) ? findings : (findings.findings || []);
const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf-8'));

function resolveFilePath(rawPath) {
  if (!rawPath) return null;
  if (fs.existsSync(rawPath)) return rawPath;
  const basename = path.basename(rawPath);
  const searchDirs = [
    process.cwd(),
    path.join(__dirname, '..', 'samples'),
    path.join(__dirname, '..', 'samples', 'js'),
    path.join(__dirname, '..')
  ];
  for (const dir of searchDirs) {
    const candidate = path.join(dir, basename);
    if (fs.existsSync(candidate)) return candidate;
  }
  const allJs = [];
  for (const dir of searchDirs) {
    if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
      try {
        allJs.push(...fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => path.join(dir, f)));
      } catch (e) {}
    }
  }
  for (const fp of allJs) {
    if (fp.endsWith(basename) || fp.includes(basename)) return fp;
  }
  if (allJs.length > 0) return allJs[0];
  return null;
}

function getFileContent(filePath) {
  try {
    const resolved = resolveFilePath(filePath);
    if (resolved) return fs.readFileSync(resolved, 'utf-8');
  } catch (e) {}
  return '';
}

function getContextAround(content, code, maxLines = 200) {
  const idx = content.indexOf(code.substring(0, Math.min(code.length, 80)));
  if (idx === -1) return '';
  const before = content.substring(Math.max(0, idx - 500), idx);
  const after = content.substring(idx, idx + 500);
  return before + after;
}

function checkContextCondition(finding, condition, value, content) {
  const code = finding.code || '';
  const context = getContextAround(content, code);

  switch (condition) {
    case 'surrounding_contains':
      return new RegExp(value, 'i').test(context);
    case 'preceding_line_contains':
      return new RegExp(value, 'i').test(context.substring(0, 400));
    case 'preceding_var_contains':
      const lines = context.split('\n');
      for (const line of lines) {
        if (line.includes(finding.code ? finding.code.trim().substring(0, 30) : '--') || true) {
          if (new RegExp(value, 'i').test(line)) return true;
        }
      }
      return new RegExp(value, 'i').test(context);
    default:
      return new RegExp(value, 'i').test(context);
  }
}

function matchMinifiedLibrary(finding) {
  const code = (finding.code || '').toLowerCase();
  const file = ((finding.file || '') + (finding.filePath || '')).toLowerCase();
  return rules.minified_library_patterns.exact_strings.some(lib =>
    code.includes(lib.toLowerCase()) || file.includes(lib.toLowerCase())
  );
}

function matchWebpackRuntime(finding) {
  const code = finding.code || '';
  return rules.webpack_runtime_patterns.patterns.some(p => {
    const re = new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    return re.test(code);
  });
}

function matchContextFreeFP(finding) {
  const code = finding.code || '';
  return rules.context_free_false_positives.patterns.some(p => {
    const re = new RegExp(p, 'i');
    return re.test(code);
  });
}

function matchKnownRegexRule(finding, content) {
  for (const rule of rules.false_positive_regexes.rules) {
    const re = new RegExp(rule.match_pattern, 'i');
    if (!re.test(finding.code || '')) continue;
    if (rule.condition) {
      if (!checkContextCondition(finding, rule.condition, rule.value, content)) continue;
    }
    return rule;
  }
  return null;
}

function matchHtmlFile(finding, content) {
  const patterns = rules.html_misclassified_as_js && rules.html_misclassified_as_js.patterns || [];
  return patterns.some(p => content.includes(p));
}

function matchFilePattern(finding) {
  const file = finding.file || finding.filePath || '';
  for (const rule of rules.false_positive_context_rules.file_pattern_rules) {
    if (new RegExp(rule.pattern, 'i').test(file)) return rule;
  }
  return null;
}

function matchSeverityDowngrade(finding, content) {
  for (const rule of rules.severity_downgrade_rules.rules) {
    const re = new RegExp(rule.pattern, 'i');
    if (!re.test(finding.code || '')) continue;
    if (rule.condition) {
      if (!checkContextCondition(finding, rule.condition, rule.value, content)) continue;
    }
    return rule;
  }
  return null;
}

function matchCorrelationRule(finding, allFindings) {
  const code = finding.code || '';
  for (const rule of rules.correlation_rules.required_pairs) {
    const primaryRe = new RegExp(rule.primary, 'i');
    if (!primaryRe.test(code)) continue;
    const secondaryRe = new RegExp(rule.secondary, 'i');
    const nearby = allFindings.filter(af => {
      if (af === finding) return false;
      const sameFile = (af.file || af.filePath) === (finding.file || finding.filePath);
      const sameLine = Math.abs((af.line || 0) - (finding.line || 0)) <= (rule.distance_max || 20);
      return sameFile && sameLine && secondaryRe.test(af.code || '');
    });
    if (nearby.length > 0) return rule;
  }
  return null;
}

const filtered = [];
const removalLog = { removed: 0, downgraded: 0, kept: 0, reasons: {} };

function logRemoval(reason, finding) {
  if (!removalLog.reasons[reason]) removalLog.reasons[reason] = 0;
  removalLog.reasons[reason]++;
}

arrayInput.forEach(finding => {
  const content = getFileContent(finding.filePath || finding.file || '');
  let action = 'KEEP';

  if (matchHtmlFile(finding, content)) { action = 'REMOVE'; logRemoval('HTML mislabeled as JS', finding); }
  else if (matchContextFreeFP(finding)) { action = 'REMOVE'; logRemoval('Context-free FP', finding); }
  else if (matchWebpackRuntime(finding)) { action = 'REMOVE'; logRemoval('Webpack runtime', finding); }
  else if (matchMinifiedLibrary(finding)) { action = 'DOWNGRADE_INFO'; logRemoval('Minified library', finding); }
  else {
    const fpRule = matchKnownRegexRule(finding, content);
    if (fpRule) {
      action = fpRule.action || 'DOWNGRADE';
      logRemoval(`Known regex rule: ${fpRule.id}`, finding);
    }
  }

  if (action === 'REMOVE') {
    removalLog.removed++;
    return;
  }

  const fileRule = matchFilePattern(finding);
  if (fileRule) {
    if (fileRule.action === 'REMOVE_ALL') {
      removalLog.removed++;
      logRemoval(`File pattern: ${fileRule.description}`, finding);
      return;
    }
    if (fileRule.action === 'DOWNGRADE_ALL_TO_LOW') {
      finding.severity = 'LOW';
      finding.cvss = Math.min(finding.cvss || 5, 3.0);
      removalLog.downgraded++;
    }
  }

  const sevRule = matchSeverityDowngrade(finding, content);
  if (sevRule) {
    if (sevRule.new_severity) {
      finding._originalSeverity = finding.severity;
      finding.severity = sevRule.new_severity;
    }
    if (sevRule.new_cvss !== undefined) {
      finding._originalCvss = finding.cvss;
      finding.cvss = sevRule.new_cvss;
    }
    finding._severityReason = sevRule.reason;
    removalLog.downgraded++;
    logRemoval(`Severity downgrade: ${sevRule.id}`, finding);
  }

  if (matchCorrelationRule(finding, arrayInput)) {
    const corrRule = matchCorrelationRule(finding, arrayInput);
    if (corrRule && corrRule.action === 'UPGRADE_CRITICAL') {
      finding.severity = 'CRITICAL';
      finding.cvss = Math.max(finding.cvss || 5, 8.5);
      finding._upgradeReason = corrRule.reason;
      logRemoval(`Correlation upgrade: ${corrRule.id}`, finding);
    }
  }

  if (action === 'DOWNGRADE_INFO') {
    finding.severity = 'INFO';
    finding.cvss = 0;
    finding._fpOverridden = true;
    removalLog.downgraded++;
  }

  removalLog.kept++;
  filtered.push(finding);
});

const result = {
  metadata: {
    filterDate: new Date().toISOString(),
    inputCount: arrayInput.length,
    outputCount: filtered.length,
    removed: removalLog.removed,
    downgraded: removalLog.downgraded,
    kept: removalLog.kept,
    reduction: arrayInput.length > 0 ? Math.round((1 - filtered.length / arrayInput.length) * 100) + '%' : '0%'
  },
  removalBreakdown: removalLog.reasons,
  findings: filtered
};

console.log('');
console.log('========================================');
console.log('  False Positive Filter Results');
console.log('========================================');
console.log(`  Input findings:     ${result.metadata.inputCount}`);
console.log(`  Removed:            ${result.metadata.removed}`);
console.log(`  Downgraded:         ${result.metadata.downgraded}`);
console.log(`  Output findings:    ${result.metadata.outputCount}`);
console.log(`  Reduction:          ${result.metadata.reduction}`);
console.log('');
console.log('  Removal breakdown:');
Object.keys(removalLog.reasons).sort().forEach(r => {
  console.log(`    - ${r}: ${removalLog.reasons[r]}`);
});
console.log('');

if (outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log(`[OK] Filtered output written to ${outputPath}`);
} else {
  console.log(JSON.stringify(result, null, 2));
}
