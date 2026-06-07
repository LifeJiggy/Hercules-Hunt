const { BrowserAutomation } = require('./browser-automation');
const { SessionHijacker } = require('./session-hijacker');
const { XSSHunter } = require('./xss-hunter');
const { CSRFTester } = require('./csrf-tester');
const { PrototypePollution } = require('./prototype-pollution');
const { PostMessageExplorer } = require('./postmessage-explorer');
const { StorageAuditor } = require('./storage-auditor');
const { EventInspector } = require('./event-inspector');
const fs = require('fs');
const path = require('path');

class ClientSideScanner {
  constructor(options = {}) {
    this.headless = options.headless !== false;
    this.outputDir = options.outputDir || 'output/client-side-scan';
    this.ba = null;
    this.findings = [];
    this.startTime = null;
  }

  async scan(url) {
    this.startTime = Date.now();
    console.log(`\n\x1b[35m=== Jiggy-2026 Client-Side Security Scanner ===\x1b[0m`);
    console.log(`\x1b[36m  Target: ${url}\x1b[0m\n`);

    this.ba = new BrowserAutomation({ headless: this.headless });
    await this.ba.launch();
    await this.ba.navigate(url);
    await this.ba.interceptResponses();

    const tools = [
      { name: 'Session Hijacker', class: SessionHijacker, severity: 'High' },
      { name: 'Storage Auditor', class: StorageAuditor, severity: 'Critical' },
      { name: 'CSRF Tester', class: CSRFTester, severity: 'High' },
      { name: 'Event Inspector', class: EventInspector, severity: 'Medium' },
      { name: 'Prototype Pollution', class: PrototypePollution, severity: 'Critical' },
      { name: 'PostMessage Explorer', class: PostMessageExplorer, severity: 'Critical' },
      { name: 'XSS Hunter', class: XSSHunter, severity: 'Critical' }
    ];

    const results = {};
    for (const tool of tools) {
      try {
        console.log(`  \x1b[33m[→]\x1b[0m Running ${tool.name}...`);
        const instance = new tool.class(this.ba.page);
        const scanMethod = instance.fullAudit || instance.fullScan || instance.testAllVectors;
        if (scanMethod) {
          const result = await (tool.name === 'Session Hijacker' ? instance.fullSessionAudit(url) : scanMethod(url || this.ba.page.url()));
          results[tool.name] = result;
          if (instance.findings) {
            this.findings.push(...instance.findings.map(f => ({ ...f, tool: tool.name })));
          }
          const findingCount = result.totalFindings || instance.findings?.length || 0;
          console.log(`  \x1b[32m[✓]\x1b[0m ${tool.name} — ${findingCount} finding(s)`);
        } else {
          const result = await instance.fullAudit();
          results[tool.name] = result;
          if (instance.findings) this.findings.push(...instance.findings.map(f => ({ ...f, tool: tool.name })));
        }
      } catch (e) {
        console.log(`  \x1b[31m[✗]\x1b[0m ${tool.name} — Error: ${e.message}`);
        results[tool.name] = { error: e.message };
      }
    }

    await this.ba.close();
    const elapsed = ((Date.now() - this.startTime) / 1000).toFixed(1);
    console.log(`\n\x1b[35m  Scan completed in ${elapsed}s — ${this.findings.length} total findings\x1b[0m`);

    return this.generateReport(results, url, elapsed);
  }

  prioritizeFindings() {
    const sev = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    return this.findings.sort((a, b) => (sev[b.severity] || 0) - (sev[a.severity] || 0));
  }

  generateReport(results, url, elapsed) {
    const prioritized = this.prioritizeFindings();
    const critical = prioritized.filter(f => f.severity === 'CRITICAL');
    const high = prioritized.filter(f => f.severity === 'HIGH');
    const medium = prioritized.filter(f => f.severity === 'MEDIUM');
    const low = prioritized.filter(f => f.severity === 'LOW');

    const report = {
      scanInfo: { target: url, timestamp: new Date().toISOString(), elapsed: `${elapsed}s`, toolsRun: 7 },
      summary: { total: this.findings.length, critical: critical.length, high: high.length, medium: medium.length, low: low.length },
      criticalFindings: critical,
      highFindings: high,
      mediumFindings: medium,
      lowFindings: low,
      rawResults: results
    };

    fs.mkdirSync(this.outputDir, { recursive: true });
    const jsonPath = path.join(this.outputDir, 'client-side-scan.json');
    fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));

    const mdPath = path.join(this.outputDir, 'client-side-scan.md');
    const md = this.renderMarkdown(report, url);
    fs.writeFileSync(mdPath, md);

    console.log(`  \x1b[32m[✓]\x1b[0m Report: ${mdPath}`);
    console.log(`  \x1b[32m[✓]\x1b[0m JSON:   ${jsonPath}`);

    return report;
  }

  renderMarkdown(report, url) {
    const lines = [
      `# Client-Side Security Scan Report`,
      ``,
      `**Target:** ${url}`,
      `**Date:** ${report.scanInfo.timestamp}`,
      `**Duration:** ${report.scanInfo.elapsed}`,
      `**Tools:** ${report.scanInfo.toolsRun}`,
      ``,
      `## Summary`,
      ``,
      `| Severity | Count |`,
      `|----------|-------|`,
      `| ${'CRITICAL'.padEnd(8)} | ${report.summary.critical} |`,
      `| ${'HIGH'.padEnd(8)} | ${report.summary.high} |`,
      `| ${'MEDIUM'.padEnd(8)} | ${report.summary.medium} |`,
      `| ${'LOW'.padEnd(8)} | ${report.summary.low} |`,
      `| **TOTAL** | **${report.summary.total}** |`,
      ``
    ];

    const sections = [
      { title: 'Critical Findings', items: report.criticalFindings },
      { title: 'High Findings', items: report.highFindings },
      { title: 'Medium Findings', items: report.mediumFindings },
      { title: 'Low Findings', items: report.lowFindings }
    ];

    for (const { title, items } of sections) {
      if (!items.length) continue;
      lines.push(`## ${title}`, '');
      for (const item of items) {
        lines.push(`- **${item.tool || 'Scanner'}**: ${item.detail || item.issue || item.finding || 'No detail'}`);
        if (item.type) lines.push(`  - Type: \`${item.type}\``);
        if (item.severity) lines.push(`  - Severity: ${item.severity}`);
        if (item.count) lines.push(`  - Occurrences: ${item.count}`);
        lines.push('');
      }
    }

    lines.push(`## P1 Warrior Action Items`, ``);
    lines.push(`### Immediate (Critical)`, ``);
    for (const f of report.criticalFindings) {
      lines.push(`- [ ] **${f.tool}**: ${f.detail || f.issue || f.finding}`);
    }
    lines.push('');
    lines.push(`### Next Session (High)`, ``);
    for (const f of report.highFindings) {
      lines.push(`- [ ] **${f.tool}**: ${f.detail || f.issue || f.finding}`);
    }
    lines.push('');
    lines.push('---');
    lines.push('*Generated by Jiggy-2026 ClientSideScanner*');

    return lines.join('\n');
  }
}

async function main() {
  const url = process.argv[2];
  if (!url) {
    console.log('Usage: node client-side-scanner.js <url>');
    console.log('Example: node client-side-scanner.js https://target.com');
    process.exit(1);
  }
  const scanner = new ClientSideScanner({ headless: process.argv.includes('--headless') });
  await scanner.scan(url);
}

if (require.main === module) main().catch(console.error);

module.exports = { ClientSideScanner };
