const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log(`Usage: node post-processor.js <findings.json> [--output final.json]`);
  console.log(`  Chains: false-positive-filter → deduplicator → severity-matcher`);
  process.exit(1);
}

const inputPath = args[0];
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : 'js-chunk-toolkit/output/final-findings.json';

const utilsDir = path.join(__dirname, '..', 'utils');
const configDir = path.join(__dirname, '..', 'config');
const stepsDir = path.join(__dirname, '..', 'output', 'steps');

fs.mkdirSync(stepsDir, { recursive: true });

function runStep(name, script, extraArgs = '', input) {
  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Step: ${name}`);
  console.log(`${'='.repeat(55)}`);

  const stepInput = path.join(stepsDir, `input-${name.replace(/\s+/g, '-').toLowerCase()}.json`);
  const stepOutput = path.join(stepsDir, `output-${name.replace(/\s+/g, '-').toLowerCase()}.json`);

  fs.writeFileSync(stepInput, JSON.stringify(input, null, 2));

  const cmd = `node "${path.join(utilsDir, script)}" "${stepInput}" --output "${stepOutput}" ${extraArgs}`;
  try {
    const result = execSync(cmd, { encoding: 'utf-8', maxBuffer: 10 * 1024 * 1024 });
    console.log(result.substring(0, 500));
    const output = JSON.parse(fs.readFileSync(stepOutput, 'utf-8'));
    return { output, path: stepOutput };
  } catch (e) {
    console.error(`  [ERROR] ${name} failed: ${e.message}`);
    if (e.stdout) console.log(e.stdout.toString().substring(0, 500));
    if (e.stderr) console.error(e.stderr.toString().substring(0, 500));
    return { output: { findings: input }, path: null };
  }
}

console.log('');
console.log('========================================');
console.log('  Post-Processor — Full Pipeline');
console.log('========================================');
console.log(`  Input:  ${inputPath}`);

const rawInput = JSON.parse(fs.readFileSync(inputPath, 'utf-8'));
const rawFindings = Array.isArray(rawInput) ? rawInput : (rawInput.findings || []);

console.log(`  Raw findings: ${rawFindings.length}`);
console.log(`  Steps dir:    ${stepsDir}`);

const fpResult = runStep('False Positive Filter', 'false-positive-filter.js', `--rules "${path.join(configDir, 'false-positive-rules.json')}"`, rawFindings);

const dedupInput = fpResult.output.findings || rawFindings;
const dedupResult = runStep('Deduplication', 'deduplicator.js', '', dedupInput);

const scoreInput = dedupResult.output.findings || dedupInput;
const scoreResult = runStep('Severity Scoring', 'severity-matcher.js', `--matrix "${path.join(configDir, 'severity-matrix.json')}"`, scoreInput);

const finalFindings = scoreResult.output.findings || scoreInput;

const finalCount = {
  CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0
};
finalFindings.forEach(f => {
  const sev = f.severity || 'INFO';
  if (finalCount[sev] !== undefined) finalCount[sev]++;
});

const result = {
  metadata: {
    processedDate: new Date().toISOString(),
    inputRaw: rawFindings.length,
    afterFalsePositiveFilter: (fpResult.output.findings || []).length,
    afterDeduplication: (dedupResult.output.findings || []).length,
    finalOutput: finalFindings.length,
    reduction: rawFindings.length > 0 ? Math.round((1 - finalFindings.length / rawFindings.length) * 100) + '%' : '0%',
    severityDistribution: finalCount,
    pipeline: {
      falsePositiveFilter: fpResult.path || 'skipped',
      deduplication: dedupResult.path || 'skipped',
      severityScoring: scoreResult.path || 'skipped'
    }
  },
  findings: finalFindings
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));

console.log('');
console.log('========================================');
console.log('  Post-Processor Complete');
console.log('========================================');
console.log(`  Raw findings:         ${result.metadata.inputRaw}`);
console.log(`  After FP filter:      ${result.metadata.afterFalsePositiveFilter}`);
console.log(`  After dedup:          ${result.metadata.afterDeduplication}`);
console.log(`  Final output:         ${result.metadata.finalOutput}`);
console.log(`  Reduction:            ${result.metadata.reduction}`);
console.log('');
console.log('  Final severity distribution:');
Object.entries(finalCount).filter(([_, c]) => c > 0).forEach(([sev, count]) => {
  console.log(`    ${sev.padEnd(10)}: ${count}`);
});
console.log('');
console.log(`[OK] Final output written to ${outputPath}`);
