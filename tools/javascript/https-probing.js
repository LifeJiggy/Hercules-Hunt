#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const tls = require('tls');
const crypto = require('crypto');
const { URL } = require('url');

const MAX_URL_LENGTH = 8192;

/**
 * @typedef {Object} HttpsProbingOptions
 * @property {string} target - Target hostname
 * @property {string} [url] - Full URL to probe
 * @property {string} [output] - Output file path
 * @property {boolean} [checkCert=true] - Perform certificate analysis
 * @property {boolean} [cipherScan=true] - Scan cipher suites
 * @property {number} [timeout=10000] - Connection timeout
 * @property {boolean} [silent=false] - Suppress verbose output
 * @property {number} [port=443] - Target port
 */

class HttpsProber {
  constructor(options = {}) {
    this.target = options.target || '';
    this.targetUrl = options.url || '';
    this.checkCert = options.checkCert !== undefined ? options.checkCert : true;
    this.cipherScan = options.cipherScan !== undefined ? options.cipherScan : true;
    this.timeout = options.timeout || 10000;
    this.silent = options.silent || false;
    this.port = options.port || 443;
    this.userAgent = 'Hercules-Hunt-HTTPS-Prober/1.0';
    this.results = {};
    this.cipherSuites = [
      'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
      'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
      'TLS_RSA_WITH_AES_128_GCM_SHA256', 'TLS_RSA_WITH_AES_256_GCM_SHA384',
      'TLS_RSA_WITH_AES_128_CBC_SHA', 'TLS_RSA_WITH_AES_256_CBC_SHA',
      'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA',
      'TLS_RSA_WITH_RC4_128_MD5', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
      'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_DH_anon_WITH_RC4_128_MD5',
      'TLS_ECDH_anon_WITH_AES_128_CBC_SHA', 'TLS_NULL_WITH_NULL_NULL',
      'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
    ];
    this.weakCiphers = [
      'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'TLS_RSA_WITH_RC4_128_SHA',
      'TLS_RSA_WITH_RC4_128_MD5', 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
      'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
      'TLS_DH_anon_WITH_AES_128_CBC_SHA', 'TLS_DH_anon_WITH_RC4_128_MD5',
      'TLS_ECDH_anon_WITH_AES_128_CBC_SHA', 'TLS_NULL_WITH_NULL_NULL',
    ];
    this.scoringCiphers = {
      'TLS_AES_128_GCM_SHA256': 'excellent', 'TLS_AES_256_GCM_SHA384': 'excellent',
      'TLS_CHACHA20_POLY1305_SHA256': 'excellent',
      'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 'excellent',
      'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 'good',
      'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': 'excellent',
      'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 'good',
      'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256': 'excellent',
      'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256': 'good',
      'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256': 'good',
      'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384': 'good',
      'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA': 'weak',
      'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA': 'weak',
      'TLS_RSA_WITH_AES_128_GCM_SHA256': 'fair',
      'TLS_RSA_WITH_AES_256_GCM_SHA384': 'fair',
      'TLS_RSA_WITH_AES_128_CBC_SHA': 'weak',
      'TLS_RSA_WITH_AES_256_CBC_SHA': 'weak',
      'TLS_RSA_WITH_3DES_EDE_CBC_SHA': 'bad',
      'TLS_RSA_WITH_RC4_128_SHA': 'bad',
      'TLS_RSA_WITH_RC4_128_MD5': 'bad',
    };
  }

  /**
   * @param {string} msg
   * @param {string} [level='info']
   */
  log(msg, level = 'info') {
    if (!this.silent) process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
  }

  /**
   * Resolves target hostname and port
   * @returns {{host: string, port: number}}
   */
  resolveTarget() {
    let host = this.target;
    let port = this.port;
    if (this.targetUrl) {
      try {
        const parsed = new URL(this.targetUrl);
        host = parsed.hostname;
        port = parseInt(parsed.port, 10) || 443;
      } catch {
        throw new Error(`Invalid URL: ${this.targetUrl}`);
      }
    }
    if (!host) throw new Error('Either --target or --url is required');
    return { host, port };
  }

  /**
   * Fetches page over HTTPS and returns response with security headers
   * @param {string} hostname
   * @param {number} port
   * @returns {Promise<{status: number, headers: Object, body: string}>}
   */
  async fetchPage(hostname, port) {
    return new Promise((resolve, reject) => {
      const opts = {
        hostname,
        port,
        path: '/',
        method: 'GET',
        headers: {
          'User-Agent': this.userAgent,
          'Accept': '*/*',
        },
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const req = https.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
          });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Performs TLS socket connection to retrieve certificate
   * @param {string} hostname
   * @param {number} port
   * @returns {Promise<import('tls').PeerCertificate>}
   */
  async getCertificate(hostname, port) {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host: hostname, port, rejectUnauthorized: false, timeout: this.timeout }, () => {
        const cert = socket.getPeerCertificate();
        socket.end();
        resolve(cert);
      });
      socket.on('error', (e) => reject(new Error(`TLS error: ${e.message}`)));
      socket.on('timeout', () => { socket.destroy(); reject(new Error('TLS timeout')); });
    });
  }

  /**
   * Analyzes a certificate and returns structured info
   * @param {import('tls').PeerCertificate} cert
   * @returns {Object}
   */
  analyzeCertificate(cert) {
    if (!cert || !cert.subject) return { error: 'No certificate available' };
    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);
    const daysRemaining = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
    const totalDays = Math.floor((validTo - validFrom) / (1000 * 60 * 60 * 24));
    const san = [];
    if (cert.subjectaltname) {
      const parts = cert.subjectaltname.split(/,\s*/);
      for (const p of parts) {
        const trimmed = p.trim();
        if (trimmed.startsWith('DNS:')) san.push(trimmed.slice(4));
        else if (trimmed.startsWith('IP:')) san.push(trimmed.slice(3));
      }
    }
    const issues = [];
    const warnings = [];
    if (daysRemaining < 0) issues.push(`Certificate EXPIRED ${Math.abs(daysRemaining)} days ago`);
    else if (daysRemaining < 7) issues.push(`Certificate expires in ${daysRemaining} days - CRITICAL`);
    else if (daysRemaining < 30) warnings.push(`Certificate expires in ${daysRemaining} days - renew soon`);
    else if (daysRemaining > 825) warnings.push(`Certificate validity is ${totalDays} days - exceeds 825-day limit`);
    if (!san || san.length === 0) warnings.push('No Subject Alternative Names (SAN)');
    const issuerStr = [cert.issuer.O, cert.issuer.CN, cert.issuer.OU].filter(Boolean).join(', ') || 'Unknown';
    const isSelfSigned = issuerStr === cert.subject.CN || !cert.issuer.O;
    if (isSelfSigned) warnings.push('Self-signed certificate detected');
    const sigAlg = cert.sigalg || '';
    const weakSigAlgs = ['MD5', 'SHA1', 'SHA-1'];
    if (weakSigAlgs.some((a) => sigAlg.includes(a))) issues.push(`Weak signature algorithm: ${sigAlg}`);
    const bits = cert.bits || 0;
    if (bits < 2048) issues.push(`Weak key strength: ${bits} bits (minimum 2048)`);
    return {
      subject: cert.subject,
      issuer: cert.issuer,
      issuerStr,
      serialNumber: cert.serialNumber,
      fingerprints: {
        sha1: cert.fingerprint,
        sha256: cert.fingerprint256,
      },
      validity: {
        from: cert.valid_from,
        to: cert.valid_to,
        daysRemaining,
        totalDays,
        expired: daysRemaining < 0,
        expiringSoon: daysRemaining >= 0 && daysRemaining < 30,
      },
      san,
      sanCount: san.length,
      signatureAlgorithm: sigAlg,
      keySize: bits,
      publicKey: cert.pubkey ? cert.pubkey.toString('base64').slice(0, 64) + '...' : null,
      selfSigned: isSelfSigned,
      issues,
      warnings,
      raw: cert,
    };
  }

  /**
   * Probes cipher suites by connecting with specific ones
   * @param {string} hostname
   * @param {number} port
   * @returns {Promise<Array<{cipher: string, supported: boolean, score: string}>>}
   */
  async scanCiphers(hostname, port) {
    const results = [];
    for (const cipher of this.cipherSuites) {
      try {
        await new Promise((resolve, reject) => {
          const socket = tls.connect({
            host: hostname, port, timeout: 3000,
            rejectUnauthorized: false, ciphers: cipher,
          }, () => {
            const negotiated = socket.getCipher();
            socket.end();
            if (negotiated && negotiated.name) {
              results.push({
                cipher: negotiated.name,
                supported: true,
                score: this.scoringCiphers[negotiated.name] || 'unknown',
                version: negotiated.version,
                bits: negotiated.bits,
              });
            } else {
              results.push({ cipher, supported: true, score: 'unknown' });
            }
            resolve();
          });
          socket.on('error', () => { results.push({ cipher, supported: false, score: 'n/a' }); resolve(); });
          socket.on('timeout', () => { socket.destroy(); results.push({ cipher, supported: false, score: 'n/a' }); resolve(); });
        });
      } catch { results.push({ cipher, supported: false, score: 'n/a' }); }
    }
    return results;
  }

  /**
   * Analyzes security headers
   * @param {Object} headers
   * @returns {Array<{header: string, value: string, status: string, description: string}>}
   */
  analyzeSecurityHeaders(headers) {
    const results = [];
    const headerChecks = {
      'strict-transport-security': {
        severity: 'medium', good: true, desc: 'HTTP Strict Transport Security (HSTS)',
        analyze: (v) => {
          const hasMaxAge = v.includes('max-age=');
          const maxAgeMatch = v.match(/max-age=(\d+)/);
          const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
          const includeSubDomains = v.includes('includeSubDomains');
          const preload = v.includes('preload');
          return { present: true, maxAge, includeSubDomains, preload, maxAgeDays: Math.floor(maxAge / 86400) };
        },
      },
      'content-security-policy': {
        severity: 'high', good: true, desc: 'Content Security Policy (CSP)',
        analyze: (v) => {
          const directives = v.split(';').map((d) => d.trim()).filter(Boolean);
          const hasUnsafeInline = v.includes("'unsafe-inline'");
          const hasUnsafeEval = v.includes("'unsafe-eval'");
          const hasWildcard = v.includes('*');
          return { present: true, directiveCount: directives.length, hasUnsafeInline, hasUnsafeEval, hasWildcard };
        },
      },
      'x-content-type-options': {
        severity: 'medium', good: (v) => v.toLowerCase() === 'nosniff', desc: 'X-Content-Type-Options',
      },
      'x-frame-options': {
        severity: 'medium', good: (v) => ['deny', 'sameorigin'].includes(v.toLowerCase()),
        desc: 'X-Frame-Options (Clickjacking protection)',
      },
      'x-xss-protection': {
        severity: 'low', good: (v) => v.includes('1; mode=block') || v === '1', desc: 'X-XSS-Protection',
      },
      'referrer-policy': {
        severity: 'low', good: (v) => ['no-referrer', 'same-origin', 'strict-origin'].includes(v.toLowerCase()),
        desc: 'Referrer-Policy',
      },
      'permissions-policy': {
        severity: 'low', good: true, desc: 'Permissions-Policy (Feature Policy)',
      },
    };
    for (const [header, config] of Object.entries(headerChecks)) {
      const value = headers[header];
      if (value) {
        const analyzed = config.analyze ? config.analyze(value) : null;
        const good = typeof config.good === 'function' ? config.good(value) : config.good;
        results.push({
          header,
          value: typeof value === 'string' ? value : JSON.stringify(value),
          status: good ? 'present' : 'present-weak',
          severity: config.severity,
          description: config.desc,
          ...(analyzed || {}),
        });
      } else {
        results.push({
          header,
          value: null,
          status: 'missing',
          severity: config.severity,
          description: config.desc,
        });
      }
    }
    const headerLeaks = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];
    for (const h of headerLeaks) {
      if (headers[h]) {
        results.push({
          header: h,
          value: headers[h],
          status: 'leak',
          severity: 'low',
          description: `Server fingerprinting via ${h} header`,
        });
      }
    }
    if (headers['set-cookie']) {
      const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : [headers['set-cookie']];
      for (const cookie of cookies) {
        if (!cookie.toLowerCase().includes('secure')) {
          results.push({
            header: 'set-cookie',
            value: cookie.slice(0, 100),
            status: 'missing-secure-flag',
            severity: 'high',
            description: 'Cookie missing Secure flag',
          });
        }
        if (!cookie.toLowerCase().includes('httponly')) {
          results.push({
            header: 'set-cookie',
            value: cookie.slice(0, 100),
            status: 'missing-httponly-flag',
            severity: 'medium',
            description: 'Cookie missing HttpOnly flag',
          });
        }
        if (!cookie.toLowerCase().includes('samesite')) {
          results.push({
            header: 'set-cookie',
            value: cookie.slice(0, 100),
            status: 'missing-samesite-flag',
            severity: 'medium',
            description: 'Cookie missing SameSite flag',
          });
        }
      }
    }
    return results;
  }

  /**
   * Performs TLS version scan
   * @param {string} hostname
   * @param {number} port
   * @returns {Promise<Array<{protocol: string, supported: boolean}>>}
   */
  async scanTlsVersions(hostname, port) {
    const versions = [
      { name: 'TLSv1.3', min: 'TLSv1.3', max: 'TLSv1.3' },
      { name: 'TLSv1.2', min: 'TLSv1.2', max: 'TLSv1.2' },
      { name: 'TLSv1.1', min: 'TLSv1.1', max: 'TLSv1.1' },
      { name: 'TLSv1', min: 'TLSv1', max: 'TLSv1' },
    ];
    const results = [];
    for (const v of versions) {
      try {
        await new Promise((resolve, reject) => {
          const socket = tls.connect({
            host: hostname, port, timeout: 5000,
            rejectUnauthorized: false, minVersion: v.min, maxVersion: v.max,
          }, () => {
            const proto = socket.getProtocol();
            socket.end();
            if (proto) {
              results.push({ protocol: v.name, supported: true, negotiated: proto });
            } else {
              results.push({ protocol: v.name, supported: true });
            }
            resolve();
          });
          socket.on('error', () => { results.push({ protocol: v.name, supported: false }); resolve(); });
          socket.on('timeout', () => { socket.destroy(); results.push({ protocol: v.name, supported: false }); resolve(); });
        });
      } catch { results.push({ protocol: v.name, supported: false }); }
    }
    return results;
  }

  /**
   * Generates the final report
   * @returns {Object}
   */
  generateReport() {
    const { host, port } = this.resolveTarget();
    const tlsInfo = this.results.tlsVersions || [];
    const enabledInsecure = tlsInfo.filter((t) => t.supported && (t.protocol === 'TLSv1' || t.protocol === 'TLSv1.1'));
    const certInfo = this.results.certificate || {};
    const cipherResults = this.results.ciphers || [];
    const weakCipherCount = cipherResults.filter((c) => c.supported && (c.score === 'bad' || c.score === 'weak')).length;
    const secureCipherCount = cipherResults.filter((c) => c.supported && (c.score === 'excellent' || c.score === 'good')).length;
    const headerIssues = this.results.securityHeaders ? this.results.securityHeaders.filter((h) => h.status === 'missing' || h.status === 'missing-secure-flag' || h.status === 'missing-httponly-flag' || h.status === 'missing-samesite-flag' || h.status === 'leak').length : 0;
    const severity = enabledInsecure.length > 0 ? 'critical' :
      certInfo.validity && certInfo.validity.expired ? 'critical' :
      weakCipherCount > 0 ? 'high' :
      headerIssues > 5 ? 'medium' : 'info';
    return {
      metadata: {
        tool: 'https-probing.js',
        timestamp: new Date().toISOString(),
        target: host,
        port,
        url: this.targetUrl || `https://${host}:${port}`,
      },
      summary: {
        overallSeverity: severity,
        certificate: {
          valid: certInfo.validity ? !certInfo.validity.expired : false,
          daysRemaining: certInfo.validity ? certInfo.validity.daysRemaining : null,
          expired: certInfo.validity ? certInfo.validity.expired : null,
          selfSigned: certInfo.selfSigned || false,
          sanCount: certInfo.sanCount || 0,
          issues: (certInfo.issues || []).length,
          warnings: (certInfo.warnings || []).length,
        },
        tls: {
          versionsTested: tlsInfo.length,
          insecureProtocols: enabledInsecure.length,
          secureProtocols: tlsInfo.filter((t) => t.supported && !enabledInsecure.includes(t)).length,
        },
        ciphers: {
          total: cipherResults.length,
          supported: cipherResults.filter((c) => c.supported).length,
          excellent: cipherResults.filter((c) => c.score === 'excellent').length,
          good: cipherResults.filter((c) => c.score === 'good').length,
          weak: cipherResults.filter((c) => c.score === 'weak').length,
          bad: cipherResults.filter((c) => c.score === 'bad').length,
        },
        securityHeaders: {
          total: this.results.securityHeaders ? this.results.securityHeaders.length : 0,
          missing: this.results.securityHeaders ? this.results.securityHeaders.filter((h) => h.status === 'missing').length : 0,
          issues: headerIssues,
        },
      },
      certificate: this.results.certificate,
      tlsVersions: tlsInfo,
      ciphers: {
        all: cipherResults,
        weak: cipherResults.filter((c) => c.supported && (c.score === 'bad' || c.score === 'weak')),
        recommended: cipherResults.filter((c) => c.supported && (c.score === 'excellent' || c.score === 'good')),
      },
      securityHeaders: this.results.securityHeaders,
      pageInfo: this.results.pageInfo || null,
    };
  }

  /**
   * Runs full HTTPS probing pipeline
   * @param {HttpsProbingOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    if (options.target && typeof options.target === 'string') {
      if (options.target.trim().length === 0) throw new Error('Target must not be empty');
      if (options.target.length > MAX_URL_LENGTH) throw new Error(`Target exceeds maximum length of ${MAX_URL_LENGTH} characters`);
      this.target = options.target;
    }
    if (options.url && typeof options.url === 'string') {
      if (options.url.trim().length === 0) throw new Error('URL must not be empty');
      if (options.url.length > MAX_URL_LENGTH) throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
      this.targetUrl = options.url;
    }
    if (options.port) this.port = options.port;
    if (options.timeout) this.timeout = options.timeout;
    if (options.checkCert !== undefined) this.checkCert = options.checkCert;
    if (options.cipherScan !== undefined) this.cipherScan = options.cipherScan;

    const { host, port } = this.resolveTarget();
    this.log(`Probing https://${host}:${port}`);

    if (this.checkCert) {
      this.log('Retrieving TLS certificate...');
      try {
        const cert = await this.getCertificate(host, port);
        this.results.certificate = this.analyzeCertificate(cert);
        this.log(`Certificate: ${this.results.certificate.subject?.CN || 'N/A'}, expires in ${this.results.certificate.validity?.daysRemaining || '?'} days`);
      } catch (err) {
        this.log(`Certificate analysis failed: ${err.message}`, 'warn');
        this.results.certificate = { error: err.message };
      }
    }

    this.log('Scanning TLS versions...');
    try {
      this.results.tlsVersions = await this.scanTlsVersions(host, port);
      const supported = this.results.tlsVersions.filter((t) => t.supported).map((t) => t.protocol);
      this.log(`TLS versions: ${supported.join(', ') || 'none'}`);
    } catch (err) {
      this.log(`TLS version scan failed: ${err.message}`, 'warn');
    }

    if (this.cipherScan) {
      this.log('Scanning cipher suites...');
      try {
        this.results.ciphers = await this.scanCiphers(host, port);
        const supported = this.results.ciphers.filter((c) => c.supported);
        const weak = supported.filter((c) => c.score === 'bad' || c.score === 'weak');
        this.log(`Ciphers: ${supported.length} supported, ${weak.length} weak/bad`);
      } catch (err) {
        this.log(`Cipher scan failed: ${err.message}`, 'warn');
      }
    }

    this.log('Fetching page and analyzing security headers...');
    try {
      const page = await this.fetchPage(host, port);
      this.results.pageInfo = {
        status: page.status,
        contentType: page.headers['content-type'] || '',
        bodyLength: page.body.length,
      };
      this.results.securityHeaders = this.analyzeSecurityHeaders(page.headers);
    } catch (err) {
      this.log(`Page fetch failed: ${err.message}`, 'warn');
    }

    const report = this.generateReport();
    this.log(`Overall severity: ${report.summary.overallSeverity.toUpperCase()}`);

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
 * @returns {HttpsProbingOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { checkCert: true, cipherScan: true, port: 443, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--target':
        options.target = args[++i];
        break;
      case '--url':
        options.url = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--check-cert':
        options.checkCert = args[++i] !== 'false';
        break;
      case '--cipher-scan':
        options.cipherScan = args[++i] !== 'false';
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i], 10);
        break;
      case '--port':
        options.port = parseInt(args[++i], 10);
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
  if (!options.target && !options.url) {
    process.stderr.write('Error: --target or --url is required\n');
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
HTTPS/TLS Probing Tool - https-probing.js
Probes HTTPS endpoints for TLS configuration and security headers.

USAGE:
  node https-probing.js --target <hostname> [options]
  node https-probing.js --url https://example.com [options]

OPTIONS:
  --target <hostname>  Target hostname (e.g. example.com)
  --url <url>          Full URL to probe (overrides --target)
  --output <path>      Write report to JSON file
  --check-cert <bool>  Perform certificate analysis (default: true)
  --cipher-scan <bool> Scan cipher suites (default: true)
  --port <number>      Target port (default: 443)
  --timeout <ms>       Connection timeout in ms (default: 10000)
  --silent             Suppress verbose output
  --help, -h           Show this help message

ANALYSIS INCLUDES:
  - TLS certificate: subject, issuer, SAN, expiry, key strength
  - TLS protocol version support (1.0, 1.1, 1.2, 1.3)
  - Cipher suite enumeration and quality scoring
  - Security headers: HSTS, CSP, XFO, X-Content-Type-Options, etc.
  - Cookie security flags (Secure, HttpOnly, SameSite)
  - Server fingerprinting header leaks
  - Weak cipher and protocol detection

EXAMPLES:
  node https-probing.js --target example.com
  node https-probing.js --url https://example.com:8443 --output tls-report.json
  node https-probing.js --target example.com --cipher-scan false --silent
`;
  process.stderr.write(help);
}

/**
 * Main
 */
async function main() {
  try {
    const options = parseArgs();
    const prober = new HttpsProber(options);
    const report = await prober.run(options);
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

module.exports = { HttpsProber };
