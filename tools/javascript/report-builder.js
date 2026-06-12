#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * @typedef {Object} Finding
 * @property {string} title - Finding title
 * @property {string} type - Vulnerability type (e.g., IDOR, XSS, SSRF)
 * @property {string} severity - Severity rating (None, Low, Medium, High, Critical)
 * @property {number} cvssScore - CVSS 3.1 base score (0.0-10.0)
 * @property {string} cvssVector - CVSS 3.1 vector string
 * @property {string} impact - Business impact description
 * @property {string} description - Technical description
 * @property {string[]} stepsToReproduce - Reproduction steps
 * @property {string} evidence - Evidence description or path
 * @property {string} remediation - Remediation recommendation
 * @property {string} target - Affected target/URL
 * @property {string} endpoint - Specific endpoint
 * @property {string} method - HTTP method used
 * @property {string} parameter - Vulnerable parameter
 * @property {Object} [metadata] - Additional metadata
 */

/**
 * @typedef {Object} CVSSMetrics
 * @property {string} AV - Attack Vector (N, A, L, P)
 * @property {string} AC - Attack Complexity (L, H)
 * @property {string} PR - Privileges Required (N, L, H)
 * @property {string} UI - User Interaction (N, R)
 * @property {string} S - Scope (U, C)
 * @property {string} C - Confidentiality (H, L, N)
 * @property {string} I - Integrity (H, L, N)
 * @property {string} A - Availability (H, L, N)
 */

/**
 * @typedef {Object} ReportBuilderOptions
 * @property {string|string[]} input - Input finding file(s), comma-separated
 * @property {string} [format='hackerone'] - Output format (hackerone, bugcrowd, markdown, json)
 * @property {string} [output] - Output file path
 * @property {string} [template='standard'] - Report template
 * @property {boolean} [batch=false] - Batch process multiple input files
 * @property {string} [author] - Report author name
 */

class ReportBuilder {
  /**
   * @param {ReportBuilderOptions} options
   */
  constructor(options = {}) {
    this.format = options.format || 'hackerone';
    this.output = options.output || '';
    this.template = options.template || 'standard';
    this.batch = options.batch || false;
    this.author = options.author || 'Hercules-Hunt Operator';
    this.silent = options.silent || false;
    this.reports = [];
  }

  /**
   * Logs message to stderr unless silent mode is active
   * @param {string} msg
   * @param {string} [level='info']
   */
  log(msg, level = 'info') {
    if (!this.silent) {
      process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
    }
  }

  /**
   * Loads findings from a JSON file
   * @param {string} inputPath
   * @returns {Finding[]}
   */
  loadFindings(inputPath) {
    if (!inputPath || typeof inputPath !== 'string') {
      throw new Error('Invalid input path: must be a non-empty string');
    }
    const resolvedPath = path.resolve(inputPath);
    if (!resolvedPath.startsWith(process.cwd())) {
      throw new Error('Path traversal detected: ' + inputPath);
    }
    if (!fs.existsSync(inputPath)) {
      throw new Error(`Input file not found: ${inputPath}`);
    }
    const st = fs.statSync(inputPath);
    if (st.size > MAX_FILE_SIZE) {
      throw new Error(`Input file exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB (${st.size} bytes)`);
    }
    this.log(`Loading findings from ${inputPath}`);
    const raw = fs.readFileSync(inputPath, 'utf-8');
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new Error(`Invalid JSON in file: ${inputPath}`);
    }
    if (Array.isArray(data)) {
      return this.validateFindings(data);
    }
    if (data.findings && Array.isArray(data.findings)) {
      return this.validateFindings(data.findings);
    }
    if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      return this.validateFindings(data.vulnerabilities);
    }
    if (data.results && Array.isArray(data.results)) {
      return this.validateFindings(data.results);
    }
    return this.validateFindings([data]);
  }

  /**
   * Validates and normalizes finding objects
   * @param {Array} findings
   * @returns {Finding[]}
   */
  validateFindings(findings) {
    return findings.map((f, i) => {
      const severity = this.normalizeSeverity(f.severity || f.risk || f.impact || 'Medium');
      const score = f.cvssScore !== undefined ? f.cvssScore : this.severityToScore(severity);
      const vector = f.cvssVector || this.scoreToVector(score);
      return {
        title: f.title || f.name || f.issue || `Finding #${i + 1}`,
        type: f.type || f.class || f.category || f.vulnerability_type || 'Unknown',
        severity,
        cvssScore: score,
        cvssVector: vector,
        impact: f.impact || f.business_impact || '',
        description: f.description || f.details || f.summary || '',
        stepsToReproduce: f.stepsToReproduce || f.reproduction_steps || f.poc || f.steps || [],
        evidence: f.evidence || f.proof || f.screenshot || '',
        remediation: f.remediation || f.recommendation || f.fix || f.mitigation || '',
        target: f.target || f.url || f.host || f.endpoint || '',
        endpoint: f.endpoint || f.path || f.route || '',
        method: f.method || f.http_method || 'GET',
        parameter: f.parameter || f.param || f.field || '',
        metadata: f.metadata || {},
        reportedBy: this.author,
        reportedAt: new Date().toISOString(),
      };
    });
  }

  /**
   * Normalizes severity string to standard values
   * @param {string} severity
   * @returns {string}
   */
  normalizeSeverity(severity) {
    const s = severity.toLowerCase();
    if (s.includes('crit')) return 'Critical';
    if (s.includes('high')) return 'High';
    if (s.includes('med')) return 'Medium';
    if (s.includes('low')) return 'Low';
    if (s.includes('none') || s.includes('info')) return 'None';
    return 'Medium';
  }

  /**
   * Converts severity to approximate CVSS score
   * @param {string} severity
   * @returns {number}
   */
  severityToScore(severity) {
    switch (severity.toLowerCase()) {
      case 'critical': return 9.5;
      case 'high': return 7.5;
      case 'medium': return 5.5;
      case 'low': return 2.5;
      case 'none': return 0.0;
      default: return 5.0;
    }
  }

  /**
   * Converts a score to a generic CVSS vector
   * @param {number} score
   * @returns {string}
   */
  scoreToVector(score) {
    if (score >= 9.0) return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    if (score >= 7.0) return 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N';
    if (score >= 4.0) return 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N';
    if (score >= 1.0) return 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N';
    return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N';
  }

  /**
   * Calculates CVSS 3.1 base score from metrics
   * @param {CVSSMetrics} metrics
   * @returns {{score: number, vector: string, severity: string}}
   */
  calculateCVSS(metrics) {
    const { AV, AC, PR, UI, S, C, I, A } = metrics;

    const avMap = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
    const acMap = { L: 0.77, H: 0.44 };
    const prMap = { N: 0.85, L: 0.62, H: 0.27 };
    const uiMap = { N: 0.85, R: 0.62 };
    const cMap = { H: 0.56, L: 0.22, N: 0 };
    const iMap = { H: 0.56, L: 0.22, N: 0 };
    const aMap = { H: 0.56, L: 0.22, N: 0 };

    const avVal = avMap[AV] || 0.85;
    const acVal = acMap[AC] || 0.77;
    const prVal = prMap[PR] || 0.85;
    const uiVal = uiMap[UI] || 0.85;

    if (S === 'U') {
      const impact = 1 - ((1 - (cMap[C] || 0)) * (1 - (iMap[I] || 0)) * (1 - (aMap[A] || 0)));
      const exploited = avVal * acVal * prVal * uiVal;
      let baseScore;
      if (impact <= 0) {
        baseScore = 0;
      } else {
        baseScore = Math.min(avVal * acVal * prVal * uiVal + impact, 10);
        baseScore = Math.round(Math.min(exploited + impact, 10) * 10) / 10;
      }
      let score = baseScore;
      const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
      const severity = this.scoreToSeverity(score);
      return { score, vector, severity };
    }

    const cImpact = 1 - ((1 - (cMap[C] || 0) * 1.0) * (1 - (iMap[I] || 0) * 1.0) * (1 - (aMap[A] || 0) * 1.0));
    const impacted = 1.0 - ((1.0 - (cMap[C] || 0)) * (1.0 - (iMap[I] || 0)) * (1.0 - (aMap[A] || 0)));
    const prScore = prMap[PR] || 0.85;
    const prChanged = S === 'C' ? 1.0 : 0.85;
    const exploited = avVal * acVal * (S === 'C' ? prScore : prScore) * uiVal;

    const impact = S === 'C' ? 1.0 - ((1.0 - (cMap[C] || 0)) * (1.0 - (iMap[I] || 0)) * (1.0 - (aMap[A] || 0))) : cImpact;
    let score;
    if (impact <= 0) {
      score = 0;
    } else {
      const exploitability = 8.22 * avVal * acVal * prScore * uiVal;
      const isImpact = S === 'C' ? 7.52 * (impact - 0.029) - 3.25 * Math.pow(impact - 0.02, 15) : 6.42 * impact;
      score = Math.round(Math.min(exploitability + isImpact, 10) * 10) / 10;
    }

    const vector = `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
    const severity = this.scoreToSeverity(score);
    return { score, vector, severity };
  }

  /**
   * Gets severity rating from CVSS score
   * @param {number} score
   * @returns {string}
   */
  scoreToSeverity(score) {
    if (score >= 9.0) return 'Critical';
    if (score >= 7.0) return 'High';
    if (score >= 4.0) return 'Medium';
    if (score >= 0.1) return 'Low';
    return 'None';
  }

  /**
   * Generates CVSS 3.1 vector string from metrics
   * @param {CVSSMetrics} metrics
   * @returns {string}
   */
  generateCVSSVector(metrics) {
    const { AV, AC, PR, UI, S, C, I, A } = metrics;
    return `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`;
  }

  /**
   * Generates a HackerOne-format report
   * @param {Finding} finding
   * @returns {string}
   */
  generateHackerOneReport(finding) {
    const steps = Array.isArray(finding.stepsToReproduce)
      ? finding.stepsToReproduce.map((s, i) => `${i + 1}. ${s}`).join('\n')
      : finding.stepsToReproduce;

    const lines = [
      `## Summary`,
      ``,
      finding.description,
      ``,
      `## Steps To Reproduce`,
      ``,
      steps || '1. Navigate to the affected endpoint\n2. Perform the request as described\n3. Observe the behavior',
      ``,
      `## Supporting Material/Evidence`,
      ``,
      finding.evidence || 'N/A',
      ``,
      `## Impact`,
      ``,
      finding.impact || 'See CVSS score for impact assessment.',
      ``,
      `## Remediation`,
      ``,
      finding.remediation || 'Apply appropriate security controls.',
      ``,
      `## CVSS 3.1 Vector`,
      ``,
      `\`${finding.cvssVector}\``,
      ``,
      `## Suggested Severity`,
      ``,
      `${finding.severity} (${finding.cvssScore.toFixed(1)})`,
      ``,
      `## Affected Target`,
      ``,
      `- **Target:** ${finding.target || 'N/A'}`,
      `- **Endpoint:** ${finding.endpoint || 'N/A'}`,
      `- **Method:** ${finding.method || 'GET'}`,
      `- **Parameter:** ${finding.parameter || 'N/A'}`,
      ``,
      `## Reporter`,
      ``,
      `${finding.reportedBy || this.author}`,
    ];

    return lines.join('\n');
  }

  /**
   * Generates a Bugcrowd-format report
   * @param {Finding} finding
   * @returns {string}
   */
  generateBugcrowdReport(finding) {
    const steps = Array.isArray(finding.stepsToReproduce)
      ? finding.stepsToReproduce.map((s, i) => `${i + 1}. ${s}`).join('\n')
      : finding.stepsToReproduce;

    const lines = [
      `## Vulnerability Description`,
      ``,
      finding.description,
      ``,
      `## Steps to Reproduce`,
      ``,
      steps || '1. Access the target URL\n2. Send the crafted request\n3. Observe the vulnerability',
      ``,
      `## Proof of Concept`,
      ``,
      finding.evidence || 'See reproduction steps.',
      ``,
      `## Impact`,
      ``,
      finding.impact || 'An attacker could exploit this vulnerability to compromise the application.',
      ``,
      `## Remediation Advice`,
      ``,
      finding.remediation || 'Implement security best practices to mitigate this vulnerability.',
      ``,
      `## Severity Request`,
      ``,
      `I am requesting **${finding.severity}** severity (CVSS: ${finding.cvssScore.toFixed(1)}) for this finding based on the following:`,
      `- **Attack Vector (AV):** Network`,
      `- **Attack Complexity (AC):** Low`,
      `- **Privileges Required (PR):** None/Low`,
      `- **User Interaction (UI):** None/Required`,
      `- **Scope (S):** Unchanged/Changed`,
      `- **Confidentiality (C):** ${finding.severity === 'Critical' ? 'High' : finding.severity === 'High' ? 'High' : 'Low'}`,
      `- **Integrity (I):** ${finding.severity === 'Critical' ? 'High' : 'Low'}`,
      `- **Availability (A):** None`,
      ``,
      `## CVSS Vector`,
      ``,
      `\`${finding.cvssVector}\``,
      ``,
      `## Affected Targets`,
      ``,
      `- **URL:** ${finding.target || 'N/A'}`,
      `- **Endpoint:** ${finding.endpoint || 'N/A'}`,
      `- **HTTP Method:** ${finding.method || 'GET'}`,
      ``,
      `## Researcher`,
      ``,
      `${finding.reportedBy || this.author}`,
    ];

    return lines.join('\n');
  }

  /**
   * Generates a generic markdown report
   * @param {Finding} finding
   * @param {string} [templateName='standard']
   * @returns {string}
   */
  generateMarkdownReport(finding, templateName = 'standard') {
    const steps = Array.isArray(finding.stepsToReproduce)
      ? finding.stepsToReproduce.map((s, i) => `${i + 1}. ${s}`).join('\n')
      : finding.stepsToReproduce;

    if (templateName === 'detailed') {
      const lines = [
        `# Security Finding Report`,
        ``,
        `---`,
        ``,
        `## Report Metadata`,
        ``,
        `| Field | Value |`,
        `|-------|-------|`,
        `| **Title** | ${finding.title} |`,
        `| **Type** | ${finding.type} |`,
        `| **Severity** | ${finding.severity} |`,
        `| **CVSS Score** | ${finding.cvssScore.toFixed(1)} |`,
        `| **CVSS Vector** | \`${finding.cvssVector}\` |`,
        `| **Reported By** | ${finding.reportedBy || this.author} |`,
        `| **Reported At** | ${finding.reportedAt} |`,
        `| **Target** | ${finding.target} |`,
        `| **Endpoint** | ${finding.endpoint} |`,
        `| **Method** | ${finding.method} |`,
        `| **Parameter** | ${finding.parameter} |`,
        ``,
        `## Description`,
        ``,
        finding.description || 'No description provided.',
        ``,
        `## Impact`,
        ``,
        finding.impact || 'No impact statement provided.',
        ``,
        `## Steps to Reproduce`,
        ``,
        steps || 'No reproduction steps provided.',
        ``,
        `## Evidence`,
        ``,
        finding.evidence || 'No evidence provided.',
        ``,
        `## Remediation`,
        ``,
        finding.remediation || 'No remediation provided.',
        ``,
        `## CVSS Breakdown`,
        ``,
        this.generateCVSSBreakdown(finding.cvssVector),
        ``,
      ];

      if (finding.metadata && Object.keys(finding.metadata).length > 0) {
        lines.push(`## Additional Metadata\n`);
        for (const [key, value] of Object.entries(finding.metadata)) {
          lines.push(`- **${key}:** ${typeof value === 'object' ? JSON.stringify(value) : value}`);
        }
        lines.push(``);
      }

      return lines.join('\n');
    }

    const lines = [
      `# ${finding.title}`,
      ``,
      `**Severity:** ${finding.severity} | **CVSS:** ${finding.cvssScore.toFixed(1)} | **Vector:** \`${finding.cvssVector}\``,
      ``,
      `**Target:** ${finding.target || 'N/A'} | **Endpoint:** ${finding.endpoint || 'N/A'} | **Method:** ${finding.method || 'GET'}`,
      ``,
      `---`,
      ``,
      `## Description`,
      ``,
      finding.description || 'No description provided.',
      ``,
      `## Impact`,
      ``,
      finding.impact || 'No impact statement provided.',
      ``,
      `## Steps to Reproduce`,
      ``,
      steps || 'No reproduction steps provided.',
      ``,
      `## Evidence`,
      ``,
      finding.evidence || 'No evidence provided.',
      ``,
      `## Remediation`,
      ``,
      finding.remediation || 'No remediation provided.',
      ``,
      `---`,
      ``,
      `*Reported by ${finding.reportedBy || this.author}*`,
    ];

    return lines.join('\n');
  }

  /**
   * Generates a CVSS breakdown from vector string
   * @param {string} vector
   * @returns {string}
   */
  generateCVSSBreakdown(vector) {
    const breakdown = [];
    const parts = vector.replace('CVSS:3.1/', '').split('/');
    const labels = {
      AV: 'Attack Vector',
      AC: 'Attack Complexity',
      PR: 'Privileges Required',
      UI: 'User Interaction',
      S: 'Scope',
      C: 'Confidentiality',
      I: 'Integrity',
      A: 'Availability',
    };
    const values = {
      N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical',
      L: 'Low', H: 'High',
      N: 'None', L: 'Low', H: 'High',
      R: 'Required',
      U: 'Unchanged', C: 'Changed',
    };

    for (const part of parts) {
      const [key, val] = part.split(':');
      if (labels[key]) {
        const friendlyVal = values[val] || val;
        breakdown.push(`- **${labels[key]} (${key}):** ${friendlyVal} (${val})`);
      }
    }

    return breakdown.join('\n');
  }

  /**
   * Generates JSON output for programmatic use
   * @param {Finding[]} findings
   * @returns {string}
   */
  generateJSONOutput(findings) {
    const report = {
      reportMetadata: {
        generatedAt: new Date().toISOString(),
        author: this.author,
        format: this.format,
        totalFindings: findings.length,
        severityBreakdown: {
          critical: findings.filter((f) => f.severity === 'Critical').length,
          high: findings.filter((f) => f.severity === 'High').length,
          medium: findings.filter((f) => f.severity === 'Medium').length,
          low: findings.filter((f) => f.severity === 'Low').length,
          none: findings.filter((f) => f.severity === 'None').length,
        },
        averageCVSS: findings.length > 0
          ? Math.round((findings.reduce((s, f) => s + f.cvssScore, 0) / findings.length) * 10) / 10
          : 0,
      },
      findings: findings.map((f) => ({
        title: f.title,
        type: f.type,
        severity: f.severity,
        cvssScore: f.cvssScore,
        cvssVector: f.cvssVector,
        target: f.target,
        endpoint: f.endpoint,
        method: f.method,
        parameter: f.parameter,
        impact: f.impact,
        description: f.description,
        stepsToReproduce: Array.isArray(f.stepsToReproduce) ? f.stepsToReproduce : [f.stepsToReproduce],
        evidence: f.evidence,
        remediation: f.remediation,
        reporter: f.reportedBy,
        reportedAt: f.reportedAt,
        metadata: f.metadata,
      })),
    };
    return JSON.stringify(report, null, 2);
  }

  /**
   * Generates a report for a single finding in the specified format
   * @param {Finding} finding
   * @returns {string}
   */
  generateReportForFinding(finding) {
    switch (this.format) {
      case 'hackerone':
        return this.generateHackerOneReport(finding);
      case 'bugcrowd':
        return this.generateBugcrowdReport(finding);
      case 'markdown':
      case 'md':
        return this.generateMarkdownReport(finding, this.template);
      case 'detailed':
        return this.generateMarkdownReport(finding, 'detailed');
      case 'json':
        return this.generateJSONOutput([finding]);
      default:
        return this.generateHackerOneReport(finding);
    }
  }

  /**
   * Generates a consolidated report for multiple findings
   * @param {Finding[]} findings
   * @returns {string}
   */
  generateMultiReport(findings) {
    if (this.format === 'json') {
      return this.generateJSONOutput(findings);
    }

    const lines = [
      `# Security Assessment Report`,
      ``,
      `**Generated:** ${new Date().toISOString()}`,
      `**Author:** ${this.author}`,
      `**Total Findings:** ${findings.length}`,
      ``,
      `## Summary`,
      ``,
      `| Severity | Count |`,
      `|----------|-------|`,
      `| Critical | ${findings.filter((f) => f.severity === 'Critical').length} |`,
      `| High     | ${findings.filter((f) => f.severity === 'High').length} |`,
      `| Medium   | ${findings.filter((f) => f.severity === 'Medium').length} |`,
      `| Low      | ${findings.filter((f) => f.severity === 'Low').length} |`,
      `| None     | ${findings.filter((f) => f.severity === 'None').length} |`,
      ``,
      `**Average CVSS Score:** ${findings.length > 0 ? (findings.reduce((s, f) => s + f.cvssScore, 0) / findings.length).toFixed(1) : 'N/A'}`,
      ``,
      `---`,
      ``,
    ];

    let counter = 1;
    for (const finding of findings) {
      const reportContent = this.generateReportForFinding(finding);
      lines.push(`## Finding #${counter}: ${finding.title}`);
      lines.push(``);
      lines.push(`**Severity:** ${finding.severity} | **CVSS:** ${finding.cvssScore.toFixed(1)} | **Vector:** \`${finding.cvssVector}\``);
      lines.push(``);
      lines.push(reportContent);
      lines.push(``);
      lines.push(`---`);
      lines.push(``);
      counter++;
    }

    return lines.join('\n');
  }

  /**
   * Batch processes multiple input files
   * @param {string[]} inputPaths
   * @returns {Promise<{findings: Finding[], reports: string[]}>}
   */
  async batchProcess(inputPaths) {
    const allFindings = [];
    const reports = [];

    for (const inputPath of inputPaths) {
      try {
        const findings = this.loadFindings(inputPath.trim());
        allFindings.push(...findings);
        for (const finding of findings) {
          const report = this.generateReportForFinding(finding);
          reports.push({ finding: finding.title, report, outputPath: '' });
        }
        this.log(`Processed ${findings.length} findings from ${path.basename(inputPath.trim())}`);
      } catch (err) {
        this.log(`Error processing ${inputPath}: ${err.message}`, 'error');
      }
    }

    if (this.output) {
      const outPath = path.resolve(this.output);
      if (!outPath.startsWith(process.cwd())) {
        console.error('Path traversal detected:', this.output);
        process.exit(1);
      }
      const ext = path.extname(outPath);
      const baseName = path.basename(outPath, ext);
      const dirName = path.dirname(outPath);

      for (let i = 0; i < reports.length; i++) {
        const f = allFindings[i];
        const safeName = f.title.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 50);
        const filePath = path.join(dirName, `${baseName}_${i + 1}_${safeName}${ext}`);
        if (!filePath.startsWith(process.cwd())) {
          console.error('Path traversal detected:', filePath);
          process.exit(1);
        }
        fs.mkdirSync(dirName, { recursive: true });
        fs.writeFileSync(filePath, reports[i].report);
        reports[i].outputPath = filePath;
        this.log(`Report written to ${filePath}`);
      }

      if (allFindings.length > 1) {
        const consolidatedPath = path.join(dirName, `${baseName}_CONSOLIDATED${ext}`);
        if (!consolidatedPath.startsWith(process.cwd())) {
          console.error('Path traversal detected:', consolidatedPath);
          process.exit(1);
        }
        const consolidated = this.generateMultiReport(allFindings);
        fs.writeFileSync(consolidatedPath, consolidated);
        this.log(`Consolidated report written to ${consolidatedPath}`);
      }
    }

    return { findings: allFindings, reports };
  }

  /**
   * Runs full report building pipeline
   * @param {ReportBuilderOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const inputPaths = Array.isArray(options.input)
      ? options.input
      : options.input.split(',').map((s) => s.trim());

    if (options.batch || inputPaths.length > 1) {
      const result = await this.batchProcess(inputPaths);
      const report = {
        totalFindings: result.findings.length,
        totalReports: result.reports.length,
        format: this.format,
        reports: result.reports.map((r) => ({ title: r.finding, output: r.outputPath })),
      };

      if (this.output && inputPaths.length === 1) {
        const outPath = path.resolve(options.output);
        if (!outPath.startsWith(process.cwd())) {
          console.error('Path traversal detected:', options.output);
          process.exit(1);
        }
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        const content = this.generateMultiReport(result.findings);
        fs.writeFileSync(outPath, content);
        this.log(`Report written to ${outPath}`);
      }

      return report;
    }

    const findings = this.loadFindings(inputPaths[0]);
    this.log(`Loaded ${findings.length} findings`);

    let outputContent;
    if (findings.length === 1) {
      outputContent = this.generateReportForFinding(findings[0]);
    } else {
      outputContent = this.generateMultiReport(findings);
    }

    if (this.output) {
      const outPath = path.resolve(options.output);
      if (!outPath.startsWith(process.cwd())) {
        console.error('Path traversal detected:', options.output);
        process.exit(1);
      }
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, outputContent);
      this.log(`Report written to ${outPath}`);
    }

    return {
      totalFindings: findings.length,
      format: this.format,
      content: outputContent,
    };
  }
}

/**
 * Parses command line arguments
 * @returns {ReportBuilderOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { format: 'hackerone', template: 'standard', batch: false, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--input':
        options.input = args[++i];
        break;
      case '--format':
        options.format = args[++i].toLowerCase();
        if (!['hackerone', 'bugcrowd', 'markdown', 'md', 'json', 'detailed'].includes(options.format)) {
          process.stderr.write(`Error: Unknown format "${options.format}". Valid: hackerone, bugcrowd, markdown, json, detailed\n`);
          process.exit(1);
        }
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--template':
        options.template = args[++i];
        break;
      case '--batch':
        options.batch = true;
        break;
      case '--author':
        options.author = args[++i];
        break;
      case '--silent':
        options.silent = true;
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
      default:
        if (args[i].startsWith('-')) {
          process.stderr.write(`Unknown option: ${args[i]}\n`);
          printHelp();
          process.exit(1);
        }
        if (!options.input) options.input = args[i];
        break;
    }
  }
  if (!options.input) {
    process.stderr.write('Error: --input is required\n');
    printHelp();
    process.exit(1);
  }
  return options;
}

/**
 * Prints help text to stderr
 */
function printHelp() {
  const help = `
Finding Report Builder - report-builder.js
Generates formatted security finding reports in HackerOne, Bugcrowd, and markdown formats.

USAGE:
  node report-builder.js --input <findings.json> [options]

OPTIONS:
  --input <path>          Input JSON file(s) containing findings (comma-separated paths)
  --format <format>       Output format: hackerone, bugcrowd, markdown, json, detailed (default: hackerone)
  --output <path>         Output file path
  --template <name>       Template name: standard, detailed (for markdown format)
  --batch                 Batch process multiple input files
  --author <name>         Report author name (default: Hercules-Hunt Operator)
  --silent                Suppress verbose output
  --help, -h              Show this help message

EXAMPLES:
  node report-builder.js --input findings.json --format hackerone --output report.md
  node report-builder.js --input findings.json --format bugcrowd
  node report-builder.js --input findings.json --format json --output report.json
  node report-builder.js --input "f1.json,f2.json" --batch --output reports/report.md
  node report-builder.js --input findings.json --format markdown --template detailed
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const builder = new ReportBuilder(options);
    const report = await builder.run(options);
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(0);
  } catch (err) {
    process.stderr.write(`FATAL ERROR: ${err.message}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { ReportBuilder };
