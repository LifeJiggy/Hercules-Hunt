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

  async scanDiff(url, previousReportPath) {
    const current = await this.scan(url);
    let previous = { summary: { total: 0 } };
    try { previous = JSON.parse(fs.readFileSync(previousReportPath, 'utf-8')); } catch {}
    const newFindings = this.findings.filter(f => !previous.summary || true);
    const delta = current.summary.total - (previous.summary?.total || 0);
    return { ...current, diff: { previousTotal: previous.summary?.total || 0, delta, newFindings: newFindings.length } };
  }

  async scanMultiple(urls) {
    const allResults = [];
    for (const url of urls) {
      console.log(`\n\x1b[36m  [→] Scanning: ${url}\x1b[0m`);
      const result = await this.scan(url);
      allResults.push({ url, ...result });
    }
    return allResults;
  }

  async scanFocused(url, toolNames) {
    const allTools = ['Session Hijacker', 'Storage Auditor', 'CSRF Tester', 'Event Inspector', 'Prototype Pollution', 'PostMessage Explorer', 'XSS Hunter'];
    const selected = allTools.filter(t => toolNames.some(s => t.toLowerCase().includes(s.toLowerCase())));
    if (!selected.length) return { error: `No tools matched: ${toolNames.join(', ')}. Available: ${allTools.join(', ')}` };
    this.ba = new BrowserAutomation({ headless: this.headless });
    await this.ba.launch();
    await this.ba.navigate(url);
    await this.ba.interceptResponses();
    const results = {};
    for (const name of selected) {
      try {
        const toolMap = {
          'Session Hijacker': SessionHijacker, 'Storage Auditor': StorageAuditor,
          'CSRF Tester': CSRFTester, 'Event Inspector': EventInspector,
          'Prototype Pollution': PrototypePollution, 'PostMessage Explorer': PostMessageExplorer,
          'XSS Hunter': XSSHunter
        };
        const Klass = toolMap[name];
        const instance = new Klass(this.ba.page);
        const scanMethod = Klass === SessionHijacker ? 'fullSessionAudit' : Klass === PrototypePollution ? 'testAllVectors' : 'fullScan';
        const result = await (scanMethod === 'fullSessionAudit' ? instance.fullSessionAudit(url) : instance[scanMethod](url));
        results[name] = result;
        if (instance.findings) this.findings.push(...instance.findings.map(f => ({ ...f, tool: name })));
      } catch (e) { results[name] = { error: e.message }; }
    }
    await this.ba.close();
    return this.generateReport(results, url, '0');
  }

  setWebhook(url) { this.webhookUrl = url; return this; }

  async notifyWebhook(report) {
    if (!this.webhookUrl) return;
    const https = require('https');
    const data = JSON.stringify({ event: 'scan-complete', summary: report.summary, timestamp: new Date().toISOString() });
    try {
      await new Promise((resolve, reject) => {
        const req = https.request(this.webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' } }, resolve);
        req.write(data);
        req.end();
      });
    } catch {}
  }

  setOutputTemplate(fn) { this.customTemplateFn = fn; return this; }

  generateHTMLReport(report) {
    const lines = [`<!DOCTYPE html><html><head><title>Client-Side Scan: ${report.scanInfo.target}</title>`];
    lines.push('<style>body{font-family:monospace;padding:20px;background:#1a1a2e;color:#eee}.critical{color:#ff4444}.high{color:#ff8800}.medium{color:#ffcc00}.low{color:#88ccff}.summary{display:flex;gap:20px}.stat{padding:15px;border-radius:8px;text-align:center;min-width:80px}.stat.crit{background:#ff444422}.stat.hi{background:#ff880022}.stat.med{background:#ffcc0022}.stat.lo{background:#88ccff22}.stat span{font-size:2em;display:block}.finding{margin:8px 0;padding:8px;border-left:3px solid #444}</style></head><body>');
    lines.push(`<h1>Client-Side Security Scan</h1><p>Target: ${report.scanInfo.target}</p><p>${report.scanInfo.timestamp}</p>`);
    lines.push('<div class="summary">');
    lines.push(`<div class="stat crit"><span>${report.summary.critical}</span>Critical</div>`);
    lines.push(`<div class="stat hi"><span>${report.summary.high}</span>High</div>`);
    lines.push(`<div class="stat med"><span>${report.summary.medium}</span>Medium</div>`);
    lines.push(`<div class="stat lo"><span>${report.summary.low}</span>Low</div></div><hr>`);
    for (const [sev, label] of [['criticalFindings', 'Critical'], ['highFindings', 'High'], ['mediumFindings', 'Medium'], ['lowFindings', 'Low']]) {
      const items = report[sev];
      if (!items?.length) continue;
      lines.push(`<h2 class="${label.toLowerCase()}">${label} (${items.length})</h2>`);
      items.forEach(f => { lines.push(`<div class="finding" style="border-color:${sev === 'criticalFindings' ? '#ff4444' : '#ff8800'}"><strong>${f.tool}:</strong> ${f.detail || f.issue || f.finding}</div>`); });
    }
    lines.push('</body></html>');
    const htmlPath = path.join(this.outputDir, 'client-side-scan.html');
    fs.writeFileSync(htmlPath, lines.join('\n'));
    return htmlPath;
  }

  getScore(report) {
    const weights = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
    const sevMap = {};
    this.findings.forEach(f => { sevMap[f.severity] = (sevMap[f.severity] || 0) + 1; });
    const score = Object.entries(sevMap).reduce((acc, [sev, count]) => acc + (weights[sev] || 0) * count, 0);
    const maxScore = 100;
    const severityScore = Math.max(0, maxScore - score);
    return { rawScore: score, severityScore: Math.round(severityScore), grade: severityScore >= 80 ? 'A' : severityScore >= 60 ? 'B' : severityScore >= 40 ? 'C' : severityScore >= 20 ? 'D' : 'F' };
  }

  async generateSummary(report) {
    const score = this.getScore(report);
    const summary = [
      `Target: ${report.scanInfo.target}`,
      `Score: ${score.grade} (${score.severityScore}/100)`,
      `Findings: ${report.summary.total} (C:${report.summary.critical} H:${report.summary.high} M:${report.summary.medium} L:${report.summary.low})`,
      `Duration: ${report.scanInfo.elapsed}`,
      `Top Action: ${report.criticalFindings[0]?.issue || 'No critical issues'}`
    ];
    return summary.join(' | ');
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
