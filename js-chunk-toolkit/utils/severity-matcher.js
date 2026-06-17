const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node severity-matcher.js <findings.json> [--matrix severity-matrix.json] [--output scored.json]');
  console.log('  Each finding needs: category (string), name, code, severity, cvss, file, line');
  process.exit(1);
}

const inputPath = args[0];
const matrixFlag = args.indexOf('--matrix');
const matrixPath = matrixFlag > -1 && args[matrixFlag + 1] ? args[matrixFlag + 1] : path.join(__dirname, '..', 'config', 'severity-matrix.json');
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : null;

const findings = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
const arrayInput = Array.isArray(findings) ? findings : (findings.findings || []);
const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf-8'));

function getCategoryInfo(category) {
  const exact = matrix.base_severity_by_class[category];
  if (exact) return exact;
  for (const [key, val] of Object.entries(matrix.base_severity_by_class)) {
    if (category.toLowerCase().includes(key.toLowerCase()) || key.toLowerCase().includes(category.toLowerCase())) {
      return val;
    }
  }
  return { base: 'MEDIUM', base_cvss: 5.0, range: [3.0, 7.0] };
}

function getImpactWeights(category) {
  const lower = category.toLowerCase();
  for (const [key, val] of Object.entries(matrix.impact_weights)) {
    if (lower.includes(key)) return val;
  }
  return { C: 'L', I: 'L', A: 'N', S: 'U' };
}

function getAttackVector(category) {
  for (const [key, val] of Object.entries(matrix.attack_vector_mapping)) {
    if (category.toLowerCase().includes(key.toLowerCase())) return val;
  }
  return 'N';
}

function calculateCVSS(baseCvss, impact, av) {
  const scope = impact.S || 'U';
  const ISC = 1 - ((1 - (matrix.cvss_breakdown.C.options[impact.C] || 0.22)) *
                     (1 - (matrix.cvss_breakdown.I.options[impact.I] || 0.22)) *
                     (1 - (matrix.cvss_breakdown.A.options[impact.A] || 0.0)));
  let impactSub;
  if (scope === 'U') {
    impactSub = 6.42 * ISC;
  } else {
    impactSub = 7.52 * (ISC - 0.029) - 3.25 * Math.pow(ISC - 0.02, 15);
  }
  if (impactSub <= 0) impactSub = 0;
  const exploitability = 8.22 * (matrix.cvss_breakdown.AV.options[av] || 0.85) *
    (matrix.cvss_breakdown.AC.options['L'] || 0.77) *
    (matrix.cvss_breakdown.PR.options['N'] || 0.85) *
    (matrix.cvss_breakdown.UI.options['N'] || 0.85);
  let cvss;
  if (scope === 'U') {
    cvss = Math.min(impactSub + exploitability, 10);
  } else {
    cvss = Math.min(1.08 * (impactSub + exploitability), 10);
  }
  cvss = Math.round(cvss * 10) / 10;
  return Math.max(0, Math.min(10, cvss));
}

function cvssToSeverity(cvss) {
  if (cvss >= 9.0) return 'CRITICAL';
  if (cvss >= 7.0) return 'HIGH';
  if (cvss >= 4.0) return 'MEDIUM';
  if (cvss >= 0.1) return 'LOW';
  return 'INFO';
}

function checkModifiers(finding, catInfo) {
  let cvss = catInfo.base_cvss;
  let severity = catInfo.base;
  const code = finding.code || '';
  const file = (finding.file || finding.filePath || '').toLowerCase();

  const modRules = matrix.severity_modifiers;
  if (modRules) {
    if (modRules.user_input_proximity) {
      for (const rule of modRules.user_input_proximity.rules) {
        const re = new RegExp(rule.pattern, 'i');
        if (re.test(code)) {
          const modifier = parseFloat(rule.modifier) || 0;
          cvss += modifier;
        }
      }
    }
    if (modRules.sink_type_multiplier) {
      for (const [sink, sinkInfo] of Object.entries(modRules.sink_type_multiplier.sinks)) {
        const escapedSink = sink.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(escapedSink, 'i');
        if (re.test(code)) {
          cvss = Math.min(cvss * (sinkInfo.multiplier || 1.0), sinkInfo.cap || 10);
        }
      }
    }
    if (modRules.location_modifiers) {
      for (const [loc, locInfo] of Object.entries(modRules.location_modifiers)) {
        if (file.includes(loc)) {
          cvss += parseFloat(locInfo.modifier) || 0;
          if (locInfo.cap) {
            const capLevel = { CRITICAL: 10, HIGH: 7.5, MEDIUM: 5.5, LOW: 2.5, INFO: 0 };
            const maxCvssForCap = capLevel[locInfo.cap] || 10;
            if (cvss > maxCvssForCap) cvss = maxCvssForCap;
          }
        }
      }
    }
  }

  const range = catInfo.range || [0, 10];
  cvss = Math.max(range[0], Math.min(range[1], cvss));
  severity = cvssToSeverity(cvss);

  const impact = getImpactWeights(finding.category);
  const av = getAttackVector(finding.category);
  const calculatedCvss = calculateCVSS(cvss, impact, av);

  return { cvss: Math.round(calculatedCvss * 10) / 10, severity };
}

const scoredFindings = arrayInput.map(finding => {
  if (finding._fpOverridden) {
    if (finding._originalCvss === undefined) finding._originalCvss = finding.cvss;
    if (finding._originalSeverity === undefined) finding._originalSeverity = finding.severity;
    return finding;
  }
  const catInfo = getCategoryInfo(finding.category);
  const { cvss, severity } = checkModifiers(finding, catInfo);
  if (finding._originalCvss === undefined) finding._originalCvss = finding.cvss;
  if (finding._originalSeverity === undefined) finding._originalSeverity = finding.severity;
  finding.cvss = cvss;
  finding.severity = severity;
  return finding;
});

const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
scoredFindings.forEach(f => { if (bySeverity[f.severity] !== undefined) bySeverity[f.severity]++; });

console.log('');
console.log('========================================');
console.log('  Severity Matcher Results');
console.log('========================================');
console.log(`  Findings processed: ${scoredFindings.length}`);
console.log('');
console.log('  Severity distribution:');
Object.entries(bySeverity).forEach(([sev, count]) => {
  if (count > 0) console.log(`    ${sev.padEnd(10)}: ${count}`);
});
console.log('');
console.log('  CVSS range:', Math.min(...scoredFindings.map(f => f.cvss)).toFixed(1), '-', Math.max(...scoredFindings.map(f => f.cvss)).toFixed(1));

const output = {
  metadata: {
    scoredDate: new Date().toISOString(),
    inputCount: arrayInput.length,
    severityDistribution: bySeverity
  },
  findings: scoredFindings
};

if (outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(output, null, 2));
  console.log(`\n[OK] Scored findings written to ${outputPath}`);
} else {
  console.log(JSON.stringify(output, null, 2));
}
