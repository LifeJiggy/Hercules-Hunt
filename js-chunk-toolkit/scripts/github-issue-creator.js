const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function createIssue(finding, options = {}) {
  const token = options.githubToken || process.env.GITHUB_TOKEN;
  const repo = options.repo || process.env.GITHUB_REPOSITORY;

  if (!token || !repo) {
    const fallback = path.join(__dirname, '..', 'output', 'github-issues.jsonl');
    fs.mkdirSync(path.dirname(fallback), { recursive: true });
    const entry = { timestamp: new Date().toISOString(), finding, note: 'No GITHUB_TOKEN set — saved to file' };
    fs.appendFileSync(fallback, JSON.stringify(entry) + '\n');
    console.log(`[INFO] Issue saved to ${fallback} (no GITHUB_TOKEN)`);
    return { created: false, reason: 'no-token', output: fallback };
  }

  const title = `[${finding.severity || 'MEDIUM'}] ${(finding.type || finding.pattern || 'Secret').toUpperCase()}: ${(finding.value || finding.name || '').substring(0, 60)}`;
  const body = `## Security Finding\n\n**Severity:** ${finding.severity || 'MEDIUM'}\n**Type:** ${finding.type || finding.pattern || 'Unknown'}\n**File:** ${finding.file || 'N/A'}\n**Line:** ${finding.line || 'N/A'}\n\n### Details\n\n\`\`\`\n${(finding.value || finding.description || 'See attached report').substring(0, 2000)}\n\`\`\`\n\n### Impact\n${finding.impact || 'Potential information disclosure or security control bypass.'}\n\n### Recommendation\n${finding.remediation || 'Review and rotate/revoke if confirmed.'}\n`;

  try {
    const payload = JSON.stringify({ title, body, labels: ['security', `severity-${(finding.severity || 'medium').toLowerCase()}`] });
    const result = execSync(`curl -s -X POST -H "Authorization: token ${token}" -H "Accept: application/vnd.github.v3+json" "https://api.github.com/repos/${repo}/issues" -d '${payload.replace(/'/g, "'\\''")}'`, { encoding: 'utf-8', timeout: 15000 });
    const data = JSON.parse(result);
    if (data.html_url) {
      console.log(`[OK] Issue created: ${data.html_url}`);
      return { created: true, url: data.html_url, number: data.number };
    }
    return { created: false, error: data.message || 'Unknown error' };
  } catch (e) {
    return { created: false, error: e.message };
  }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Usage: node github-issue-creator.js <findings.json> [--repo owner/repo]');
    console.log('  Requires GITHUB_TOKEN env var or --token');
    process.exit(1);
  }

  const findings = JSON.parse(fs.readFileSync(args[0], 'utf-8'));
  const input = Array.isArray(findings) ? findings : findings.findings || findings.secrets || [];
  const repoFlag = args.indexOf('--repo');

  const options = {
    githubToken: process.env.GITHUB_TOKEN,
    repo: repoFlag > -1 ? args[repoFlag + 1] : process.env.GITHUB_REPOSITORY
  };

  const critical = input.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  if (critical.length === 0) { console.log('No CRITICAL or HIGH findings to create issues for.'); process.exit(0); }

  critical.slice(0, 5).forEach(f => createIssue(f, options));
}

module.exports = { createIssue };
