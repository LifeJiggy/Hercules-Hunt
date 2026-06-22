const fs = require('fs');
const path = require('path');

function generateDraft(findings, options = {}) {
  const platform = options.platform || 'hackerone';
  const top = (Array.isArray(findings) ? findings : findings.findings || findings.secrets || [])
    .filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
    .sort((a, b) => (b.cvss_score || b.score || 0) - (a.cvss_score || a.score || 0));

  if (top.length === 0) {
    top.push(...(Array.isArray(findings) ? findings : []).slice(0, 3));
  }

  const drafts = [];
  for (const f of top.slice(0, 5)) {
    const title = `[${f.severity}] ${(f.type || f.pattern || 'Secret').toUpperCase()}: ${(f.value || f.name || '').substring(0, 60)}`;
    const summary = f.description || `${(f.type || f.pattern || 'Finding')} detected in ${f.file || 'unknown'}`;

    if (platform === 'bugcrowd') {
      drafts.push({
        vulnerability_type: f.type || f.pattern || 'Other',
        title,
        description: `**Impact:** ${f.impact || 'Information disclosure'}\n\n**Evidence:**\n- Value: \`${(f.value || '').substring(0, 200)}\`\n- File: ${f.file || 'N/A'}\n- Line: ${f.line || 'N/A'}\n\n**Remediation:** ${f.remediation || 'Rotate/revoke the exposed credential'}`,
        severity: (f.severity || 'MEDIUM').toLowerCase(),
        cvss_vector: f.cvss || ''
      });
    } else {
      drafts.push({
        vulnerability_information: `## Summary\n${summary}\n\n## Impact\n${f.impact || 'Exposure of sensitive information that could lead to account takeover or data breach.'}\n\n## Steps to Reproduce\n1. Download the JS bundle from the target\n2. Run the analysis toolkit\n3. Observe the finding\n\n## Supporting Material\n\`\`\`\nValue: ${(f.value || '').substring(0, 300)}\nFile: ${f.file || 'N/A'}\nLine: ${f.line || 'N/A'}\n\`\`\``,
        severity: f.severity || 'medium',
        title
      });
    }
  }

  return { platform, count: drafts.length, drafts };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Usage: node draft-generator.js <findings.json> [--platform hackerone|bugcrowd] [--output draft.json]');
    process.exit(1);
  }

  const findings = JSON.parse(fs.readFileSync(args[0], 'utf-8'));
  const platformFlag = args.indexOf('--platform');
  const platform = platformFlag > -1 && args[platformFlag + 1] ? args[platformFlag + 1] : 'hackerone';
  const outFlag = args.indexOf('--output');
  const outputFile = outFlag > -1 && args[outFlag + 1] ? args[outFlag + 1] : 'draft-submission.json';

  const draft = generateDraft(findings, { platform });
  fs.writeFileSync(outputFile, JSON.stringify(draft, null, 2));
  console.log(`\n[OK] ${draft.count} draft${draft.count > 1 ? 's' : ''} written to ${outputFile} (${platform})\n`);
}

module.exports = { generateDraft };
