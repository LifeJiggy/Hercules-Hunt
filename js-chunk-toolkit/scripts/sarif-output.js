const fs = require('fs');
const path = require('path');

function generateSARIF(findings, options = {}) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'JS-Chunk-Toolkit', version: '1.0.0', informationUri: 'https://github.com/js-chunk-toolkit' } },
      results: [],
      artifacts: []
    }]
  };

  const run = sarif.runs[0];
  const filesSeen = new Set();

  for (const f of findings) {
    const artifactIndex = f.file && !filesSeen.has(f.file) ? run.artifacts.length : -1;
    if (f.file && !filesSeen.has(f.file)) {
      filesSeen.add(f.file);
      run.artifacts.push({
        location: { uri: path.resolve(f.file) },
        sourceLanguage: 'javascript'
      });
    }

    const sevMap = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', info: 'note' };
    const level = sevMap[f.severity] || 'none';

    run.results.push({
      ruleId: f.type || f.pattern || f.name || 'generic-finding',
      level,
      message: { text: f.value || f.description || `${f.type || f.pattern || ''}: ${(f.value || '').substring(0, 100)}` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.file ? path.resolve(f.file) : 'unknown.js', index: f.file && filesSeen.has(f.file) ? Array.from(filesSeen).indexOf(f.file) : -1 },
          region: f.line ? { startLine: f.line } : undefined
        }
      }],
      properties: {
        severity: f.severity || 'info',
        confidence: f.confidence || 'medium',
        ...(f.cvss ? { cvss: f.cvss } : {})
      }
    });
  }

  return sarif;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Usage: node sarif-output.js <findings.json> [--output report.sarif]');
    process.exit(1);
  }

  const findings = JSON.parse(fs.readFileSync(args[0], 'utf-8'));
  const input = Array.isArray(findings) ? findings : findings.findings || findings.secrets || [];

  const outFlag = args.indexOf('--output');
  const outputFile = outFlag > -1 && args[outFlag + 1] ? args[outFlag + 1] : 'output.sarif';

  const sarif = generateSARIF(input);
  fs.writeFileSync(outputFile, JSON.stringify(sarif, null, 2));
  console.log(`\n[OK] SARIF report written to ${outputFile} (${sarif.runs[0].results.length} findings)\n`);
}

module.exports = { generateSARIF };
