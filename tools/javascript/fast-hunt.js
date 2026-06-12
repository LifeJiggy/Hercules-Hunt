#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_URL_LENGTH = 8192;

/**
 * @typedef {Object} FastHuntOptions
 * @property {string} target - Target URL
 * @property {boolean} [quick=true] - Quick mode (limited probes)
 * @property {boolean} [aggressive=false] - Aggressive mode (more probes)
 * @property {boolean} [silent=false] - Suppress verbose output
 * @property {string} [output] - Output file path
 * @property {number} [timeout=8000] - Request timeout
 */

class FastHunter {
  constructor(options = {}) {
    this.target = options.target ? options.target.replace(/\/+$/, '') : '';
    this.quick = options.quick !== undefined ? options.quick : true;
    this.aggressive = options.aggressive || false;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 8000;
    this.userAgent = 'Hercules-Hunt-Fast-Hunter/1.0';
    this.findings = [];
    this.commonPaths = [
      '/', '/admin', '/administrator', '/login', '/signin', '/signup', '/register',
      '/api', '/api/v1', '/api/v2', '/api/v3', '/api/health', '/api/status',
      '/api/docs', '/api/swagger.json', '/api/openapi.json', '/api-docs',
      '/swagger.json', '/swagger', '/openapi.json', '/graphql',
      '/.env', '/.git/config', '/.git/HEAD', '/.htaccess', '/.aws/credentials',
      '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/security.txt',
      '/wp-admin', '/wp-content', '/wp-includes', '/wp-json',
      '/config', '/config.json', '/config.php', '/configuration',
      '/db', '/database', '/backup', '/dump', '/sql', '/mysql',
      '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
      '/status', '/health', '/healthcheck', '/healthz', '/readyz',
      '/metrics', '/prometheus', '/monitoring',
      '/favicon.ico', '/manifest.json', '/browserconfig.xml',
      '/service-worker.js', '/sw.js', '/asset-manifest.json',
      '/version', '/version.txt', '/version.json', '/VERSION',
      '/proxy', '/proxy/', '/cgi-bin/', '/cpanel', '/plesk',
      '/web-console', '/jmx-console', '/manager/html',
      '/actuator', '/actuator/health', '/actuator/info', '/actuator/env',
      '/api/user', '/api/users', '/api/admin', '/api/config',
      '/.well-known/security.txt', '/.well-known/openid-configuration',
      '/oauth2/authorize', '/.well-known/oauth-authorization-server',
    ];
    this.commonMethods = ['GET', 'POST', 'OPTIONS', 'HEAD'];
    this.misconfigChecks = [
      { name: 'Directory Listing', check: (body, headers) => body.includes('Index of /') || /<title>Index of /i.test(body) },
      { name: 'Debug Mode', check: (body) => body.includes('debug') && body.includes('error') && /stack|trace|warning|notice/i.test(body) },
      { name: 'Server Info', check: (body, headers) => headers['server'] || headers['x-powered-by'] || headers['x-aspnet-version'] },
      { name: 'CORS Misconfig', check: (body, headers) => headers['access-control-allow-origin'] === '*' && headers['access-control-allow-credentials'] === 'true' },
      { name: 'Default Credentials', check: (body) => body.includes('admin') && body.includes('password') && (body.includes('login') || body.includes('signin')) },
      { name: 'API Key Leak', check: (body) => /AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|sk_live_|pk_live_/.test(body) },
      { name: 'JWT Token Leak', check: (body) => /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/.test(body) },
      { name: 'Open Redirect', check: (body) => /(window\.location|document\.location)\s*=\s*["']/.test(body) },
    ];
    this.priorityChecks = [
      { path: '/.env', severity: 'critical', type: 'Sensitive File Exposure' },
      { path: '/.git/config', severity: 'critical', type: 'Git Config Exposure' },
      { path: '/.git/HEAD', severity: 'high', type: 'Git HEAD Exposure' },
      { path: '/api/swagger.json', severity: 'high', type: 'API Documentation Exposure' },
      { path: '/graphql', severity: 'high', type: 'GraphQL Endpoint' },
      { path: '/actuator', severity: 'high', type: 'Spring Actuator Exposure' },
      { path: '/actuator/env', severity: 'critical', type: 'Environment Variables Leak' },
      { path: '/admin', severity: 'high', type: 'Admin Panel Exposure' },
      { path: '/phpinfo.php', severity: 'critical', type: 'PHP Info Exposure' },
      { path: '/wp-json', severity: 'medium', type: 'WordPress REST API' },
      { path: '/crossdomain.xml', severity: 'medium', type: 'Flash Crossdomain Policy' },
      { path: '/security.txt', severity: 'low', type: 'Security Contact' },
      { path: '/manifest.json', severity: 'low', type: 'Web Manifest' },
      { path: '/sitemap.xml', severity: 'low', type: 'Sitemap' },
      { path: '/robots.txt', severity: 'low', type: 'Robots.txt' },
    ];
  }

  /**
   * @param {string} msg
   * @param {string} [level='info']
   */
  log(msg, level = 'info') {
    if (!this.silent) process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
  }

  /**
   * @param {string} url
   * @param {string} [method='GET']
   * @param {Object} [extraHeaders={}]
   * @returns {Promise<{status: number, headers: Object, body: string, bodyLength: number, elapsed: number}>}
   */
  async request(url, method = 'GET', extraHeaders = {}) {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const headers = {
      'User-Agent': this.userAgent,
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      ...extraHeaders,
    };
    return new Promise((resolve) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers,
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const start = Date.now();
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString();
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body,
            bodyLength: body.length,
            elapsed: Date.now() - start,
          });
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', bodyLength: 0, elapsed: 0, error: 'timeout' }); });
      req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', bodyLength: 0, elapsed: 0, error: e.message }));
      req.end();
    });
  }

  /**
   * Probes a single path with all common methods
   * @param {string} path
   * @returns {Promise<Array>}
   */
  async probePath(path) {
    const findings = [];
    const url = `${this.target}${path}`;
    for (const method of this.commonMethods) {
      try {
        const res = await this.request(url, method);
        if (res.status && res.status !== 404) {
          const entry = { path, method, status: res.status, size: res.bodyLength, elapsed: res.elapsed };
          for (const check of this.misconfigChecks) {
            if (check.check(res.body, res.headers)) {
              findings.push({
                type: check.name,
                path: url,
                method,
                status: res.status,
                severity: 'medium',
                detail: `Potential ${check.name}`,
                headers: res.headers,
                bodyPreview: res.body.slice(0, 200),
              });
            }
          }
          findings.push({ type: 'Accessible Path', path: url, method, status: res.status, size: res.bodyLength, elapsed: res.elapsed, severity: 'info' });
        }
      } catch { /* skip failures */ }
    }
    return findings;
  }

  /**
   * Runs quick priority checks on common sensitive paths
   * @returns {Promise<Array>}
   */
  async runPriorityChecks() {
    const findings = [];
    for (const check of this.priorityChecks) {
      const url = `${this.target}${check.path}`;
      try {
        const res = await this.request(url, 'GET');
        if (res.status === 200 && res.bodyLength > 10) {
          const leaked = res.body.replace(/\n/g, ' ').trim().slice(0, 200);
          findings.push({
            type: check.type,
            path: check.path,
            url,
            status: res.status,
            size: res.bodyLength,
            severity: check.severity,
            evidence: leaked,
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests for CORS misconfiguration
   * @returns {Promise<Array>}
   */
  async testCors() {
    const findings = [];
    const dangerousOrigins = ['null', 'https://evil.com', 'http://evil.com', 'file://'];
    for (const origin of dangerousOrigins) {
      try {
        const res = await this.request(`${this.target}/`, 'OPTIONS', { Origin: origin });
        const acao = res.headers['access-control-allow-origin'];
        const acac = res.headers['access-control-allow-credentials'];
        if (acao === '*' || acao === origin) {
          findings.push({
            type: 'CORS Misconfiguration',
            path: '/',
            origin,
            status: res.status,
            severity: acao === '*' && acac === 'true' ? 'critical' : 'high',
            detail: `Origin reflection: ${acao}, Credentials: ${acac}`,
            headers: res.headers,
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests for open redirect
   * @returns {Promise<Array>}
   */
  async testOpenRedirect() {
    const findings = [];
    const redirectParams = ['url', 'redirect', 'return', 'next', 'redirect_uri', 'redirect_url', 'callback', 'dest', 'destination', 'goto', 'target', 'page', 'rurl', 'u', 'path', 'link', 'to'];
    const externalUrls = ['https://evil.com', '//evil.com', 'http://evil.com/test', 'https://evil.com/redirect'];
    for (const param of redirectParams) {
      for (const external of externalUrls) {
        const testUrl = `${this.target}/?${param}=${encodeURIComponent(external)}`;
        try {
          const res = await this.request(testUrl, 'GET');
          if (res.status === 301 || res.status === 302 || res.status === 307 || res.status === 308) {
            const location = res.headers['location'] || '';
            if (location.includes('evil.com')) {
              findings.push({
                type: 'Open Redirect',
                url: testUrl,
                param,
                redirectTo: location,
                status: res.status,
                severity: 'medium',
                evidence: `Redirects to: ${location}`,
              });
            }
          }
        } catch { /* skip */ }
      }
    }
    return findings;
  }

  /**
   * Tests for common debug/verb tampering endpoints
   * @returns {Promise<Array>}
   */
  async testDebugEndpoints() {
    const findings = [];
    const endpoints = [
      '/api/health', '/api/status', '/api/ping', '/api/version',
      '/actuator', '/actuator/health', '/actuator/info',
      '/status', '/health', '/healthz', '/readyz',
      '/info', '/version', '/.well-known/security.txt',
      '/api-docs', '/v2/api-docs', '/v3/api-docs',
      '/config', '/configuration',
    ];
    for (const ep of endpoints) {
      const url = `${this.target}${ep}`;
      try {
        const res = await this.request(url, 'GET');
        if (res.status === 200 && res.bodyLength > 5) {
          const isJson = res.headers['content-type'] && res.headers['content-type'].includes('json');
          findings.push({
            type: 'Exposed Debug/Admin Endpoint',
            path: ep,
            url,
            status: res.status,
            size: res.bodyLength,
            isJson,
            severity: 'medium',
            evidence: res.body.slice(0, 200),
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Tests for common header security issues
   * @returns {Promise<Array>}
   */
  async testSecurityHeaders() {
    const findings = [];
    try {
      const res = await this.request(`${this.target}/`, 'GET');
      const headers = res.headers;
      const securityHeaders = {
        'strict-transport-security': { name: 'HSTS', severity: 'medium', desc: 'Missing HSTS header' },
        'content-security-policy': { name: 'CSP', severity: 'high', desc: 'Missing Content Security Policy' },
        'x-content-type-options': { name: 'X-Content-Type-Options', severity: 'medium', desc: 'Missing X-Content-Type-Options: nosniff' },
        'x-frame-options': { name: 'X-Frame-Options', severity: 'medium', desc: 'Missing clickjacking protection' },
        'x-xss-protection': { name: 'X-XSS-Protection', severity: 'low', desc: 'Missing XSS filter header' },
        'referrer-policy': { name: 'Referrer-Policy', severity: 'low', desc: 'Missing Referrer-Policy' },
        'permissions-policy': { name: 'Permissions-Policy', severity: 'low', desc: 'Missing Permissions-Policy' },
        'cache-control': { name: 'Cache-Control', severity: 'low', desc: 'Missing Cache-Control' },
      };
      for (const [header, config] of Object.entries(securityHeaders)) {
        if (!headers[header]) {
          findings.push({
            type: 'Missing Security Header',
            header: config.name,
            severity: config.severity,
            detail: config.desc,
          });
        }
      }
      if (headers['x-powered-by']) {
        findings.push({ type: 'Server Fingerprinting', header: 'X-Powered-By', value: headers['x-powered-by'], severity: 'low', detail: `Server header leak: ${headers['x-powered-by']}` });
      }
      if (headers['server']) {
        findings.push({ type: 'Server Fingerprinting', header: 'Server', value: headers['server'], severity: 'low', detail: `Server header leak: ${headers['server']}` });
      }
    } catch { /* skip */ }
    return findings;
  }

  /**
   * Runs aggressive additional probes
   * @returns {Promise<Array>}
   */
  async runAggressiveProbes() {
    const findings = [];
    const aggressivePaths = [
      '/api/admin/users', '/api/admin/config', '/api/admin/settings',
      '/api/internal', '/api/private', '/api/debug',
      '/api/user/me', '/api/user/0', '/api/user/1', '/api/user/admin',
      '/api/users/me', '/api/users/0', '/api/users/1',
      '/api/items?limit=1000', '/api/items?page=1&limit=1000',
      '/api/orders?limit=1000', '/api/transactions?limit=1000',
      '/api/search?q=*', '/api/search?q=test', '/api/search?q=admin',
      '/api/export', '/api/export/csv', '/api/export/json',
      '/api/import', '/api/upload', '/api/upload/avatar',
      '/api/files', '/api/documents', '/api/attachments',
      '/api/webhook', '/api/webhooks', '/api/callback',
      '/api/logs', '/api/audit', '/api/audit/log',
      '/api/config/backup', '/api/backup', '/api/restore',
      '/api/migrate', '/api/migration',
      '/api/cache/flush', '/api/cache/clear',
    ];
    for (const p of aggressivePaths) {
      const url = `${this.target}${p}`;
      try {
        const res = await this.request(url, 'GET');
        if (res.status === 200 && res.bodyLength > 10) {
          findings.push({
            type: 'Accessible Internal Path',
            path: p,
            url,
            status: res.status,
            size: res.bodyLength,
            severity: 'high',
            evidence: res.body.slice(0, 200),
          });
        }
      } catch { /* skip */ }
    }
    return findings;
  }

  /**
   * Generates the final report
   * @param {Array} findings
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(findings, metadata = {}) {
    const bySeverity = {};
    const byType = {};
    for (const f of findings) {
      const sev = f.severity || 'info';
      if (!bySeverity[sev]) bySeverity[sev] = [];
      bySeverity[sev].push(f);
      const type = f.type || 'Unknown';
      if (!byType[type]) byType[type] = [];
      byType[type].push(f);
    }
    return {
      metadata: {
        tool: 'fast-hunt.js',
        timestamp: new Date().toISOString(),
        target: this.target,
        mode: this.aggressive ? 'aggressive' : this.quick ? 'quick' : 'normal',
        ...metadata,
      },
      summary: {
        totalFindings: findings.length,
        critical: (bySeverity.critical || []).length,
        high: (bySeverity.high || []).length,
        medium: (bySeverity.medium || []).length,
        low: (bySeverity.low || []).length,
        info: (bySeverity.info || []).length,
        byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length])),
      },
      findings: findings.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity] || 99) - (order[b.severity] || 99);
      }),
    };
  }

  /**
   * Runs full fast hunt
   * @param {FastHuntOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const startTime = Date.now();
    if (options.target && typeof options.target === 'string') {
      if (options.target.trim().length === 0) throw new Error('Target must not be empty');
      if (options.target.length > MAX_URL_LENGTH) throw new Error(`Target URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
      this.target = options.target.replace(/\/+$/, '');
    }
    if (!this.target) throw new Error('--target is required');

    this.log(`Starting fast hunt on ${this.target} (mode: ${this.aggressive ? 'aggressive' : 'quick'})`);
    let allFindings = [];
    const pathsToTest = this.aggressive ? this.commonPaths.concat([
      '/api/v1', '/api/v2', '/api/v3', '/api/v4',
      '/graphql', '/rest', '/soap', '/odata',
      '/.well-known/', '/.env.bak', '/.env.local', '/.env.prod',
      '/backup/', '/backup.sql', '/backup.zip', '/backup.tar.gz',
      '/.npmrc', '/.yarnrc', '/.pypirc', '/.gemrc',
      '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
      '/Jenkinsfile', '/.travis.yml', '/.circleci/config.yml',
      '/package.json', '/package-lock.json', '/yarn.lock',
      '/webpack.config.js', '/vite.config.js', '/next.config.js',
      '/tsconfig.json', '/babel.config.js',
      '/.eslintrc', '/.prettierrc', '/.stylelintrc',
      '/nginx.conf', '/.htpasswd', '/.htaccess',
      '/app.json', '/app.config.json',
    ]) : this.commonPaths;
    const priorityResults = await this.runPriorityChecks();
    allFindings.push(...priorityResults);
    const batchSize = this.aggressive ? 10 : 15;
    for (let i = 0; i < pathsToTest.length; i += batchSize) {
      const batch = pathsToTest.slice(i, i + batchSize);
      this.log(`Testing paths ${i + 1}-${Math.min(i + batchSize, pathsToTest.length)}/${pathsToTest.length}`);
      const results = await Promise.all(batch.map((p) => this.probePath(p)));
      for (const r of results) allFindings.push(...r);
    }
    const corsResults = await this.testCors();
    allFindings.push(...corsResults);
    const redirectResults = await this.testOpenRedirect();
    allFindings.push(...redirectResults);
    const secHeaders = await this.testSecurityHeaders();
    allFindings.push(...secHeaders);
    const debugResults = await this.testDebugEndpoints();
    allFindings.push(...debugResults);
    if (this.aggressive) {
      this.log('Running aggressive probes...');
      const aggressiveResults = await this.runAggressiveProbes();
      allFindings.push(...aggressiveResults);
    }
    const uniqueFindings = [];
    const seen = new Set();
    for (const f of allFindings) {
      const key = `${f.type}|${f.url || f.path || ''}|${f.severity}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueFindings.push(f);
      }
    }
    const report = this.generateReport(uniqueFindings, { elapsed: Date.now() - startTime, pathsTested: pathsToTest.length });
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
 * @returns {FastHuntOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { quick: true, aggressive: false, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--target':
        options.target = args[++i];
        break;
      case '--quick':
        options.quick = true;
        options.aggressive = false;
        break;
      case '--aggressive':
        options.aggressive = true;
        options.quick = false;
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--silent':
        options.silent = true;
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i], 10);
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
Fast Surface Hunter - fast-hunt.js
Quick security probes for low-hanging fruit and common misconfigurations.

USAGE:
  node fast-hunt.js --target <url> [options]

OPTIONS:
  --target <url>      Target URL (required)
  --quick             Quick mode — limited probes (default)
  --aggressive        Aggressive mode — extended path list and deeper checks
  --output <path>     Write findings to JSON file
  --silent            Suppress verbose output
  --timeout <ms>      Request timeout (default: 8000)
  --help, -h          Show this help message

CHECKS PERFORMED:
  - Common paths probe (admin, API, env, git, config files)
  - Priority sensitive file detection (.env, .git, actuator, etc.)
  - CORS misconfiguration testing
  - Open redirect detection
  - Missing security headers (HSTS, CSP, XFO, etc.)
  - Server fingerprinting header leaks
  - Debug endpoint discovery (aggressive mode)
  - Internal API path probing (aggressive mode)
  - Directory listing detection
  - Stack trace / error disclosure
  - API key and secret scanning in responses

EXAMPLES:
  node fast-hunt.js --target https://example.com
  node fast-hunt.js --target https://example.com --aggressive --output fast-hunt.json
  node fast-hunt.js --target https://example.com --silent > findings.json
`;
  process.stderr.write(help);
}

/**
 * Main
 */
async function main() {
  try {
    const options = parseArgs();
    const hunter = new FastHunter(options);
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

module.exports = { FastHunter };
