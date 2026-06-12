#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');

const MAX_URL_LENGTH = 8192;
const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * @typedef {Object} LoginForm
 * @property {string} action - Form action URL
 * @property {string} method - HTTP method
 * @property {Object} usernameField - Detected username/email field {name, type, id}
 * @property {Object} passwordField - Detected password field {name, type, id}
 * @property {Object|null} rememberMe - Detected remember-me field {name, value}
 * @property {Array<{name: string, type: string, value: string}>} extraFields - Other form fields
 */

/**
 * @typedef {Object} CookieAnalysis
 * @property {string} name - Cookie name
 * @property {string} value - Cookie value (truncated)
 * @property {boolean} httpOnly - HttpOnly flag
 * @property {boolean} secure - Secure flag
 * @property {string} sameSite - SameSite attribute
 * @property {string} domain - Domain
 * @property {string} path - Path
 * @property {string|null} expires - Expiry date
 * @property {number|null} maxAge - Max-Age in seconds
 * @property {boolean} sessionCookie - Whether cookie is session-only
 */

/**
 * @typedef {Object} JWTDecoded
 * @property {Object} header - JWT header
 * @property {Object} payload - JWT payload
 * @property {string} signature - Raw signature (truncated)
 * @property {string} algorithm - Signing algorithm
 * @property {string|null} issuer - Issuer claim
 * @property {string|null} subject - Subject claim
 * @property {string|null} audience - Audience claim
 * @property {number|null} issuedAt - Issued at timestamp
 * @property {number|null} expiration - Expiration timestamp
 * @property {boolean} expired - Whether token is expired
 */

/**
 * @typedef {Object} AuthTestResult
 * @property {string} test - Test name
 * @property {string} endpoint - Tested endpoint
 * @property {string} method - HTTP method
 * @property {number} status - Response status code
 * @property {Object} headers - Response headers
 * @property {number} bodySize - Response body size
 * @property {boolean} bypassed - Whether auth was bypassed
 * @property {string|null} reason - Reason for bypass detection
 */

/**
 * @typedef {Object} AuthTesterOptions
 * @property {string} [target] - Target base URL
 * @property {string} [loginUrl] - Login page URL
 * @property {string} [credentials] - Credentials JSON string or file path
 * @property {string} [method] - HTTP method for login
 * @property {string} [output] - Output file path
 * @property {boolean} [testBypasses=false] - Run auth bypass header tests
 * @property {boolean} [analyzeJwt=false] - Analyze JWT token
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class AuthTester {
  /**
   * @param {AuthTesterOptions} options
   */
  constructor(options = {}) {
    this.silent = options.silent || false;
    this.timeout = options.timeout || 15000;
    this.testBypasses = options.testBypasses || false;
    this.analyzeJwt = options.analyzeJwt || false;
    this.userAgent = 'Hercules-Hunt-Auth-Tester/1.0';
    this.results = [];
    this.cookies = [];
    this.jwtTokens = [];
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
   * Makes an HTTP request
   * @param {string} targetUrl
   * @param {string} [method='GET']
   * @param {string|null} [body=null]
   * @param {Object} [headers={}]
   * @returns {Promise<{status: number, headers: Object, body: string, elapsed: number}>}
   */
  async fetchUrl(targetUrl, method = 'GET', body = null, headers = {}) {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,*/*',
          'Accept-Language': 'en-US,en;q=0.9',
          ...headers,
        },
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const start = Date.now();
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
            elapsed: Date.now() - start,
          });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout fetching ${targetUrl}`)); });
      req.on('error', (e) => reject(new Error(`Request error for ${targetUrl}: ${e.message}`)));
      if (body) {
        req.write(body);
      }
      req.end();
    });
  }

  /**
   * Detects login form elements from HTML content
   * @param {string} content
   * @param {string} baseUrl
   * @returns {LoginForm|null}
   */
  detectLoginForm(content, baseUrl) {
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch;
    while ((formMatch = formRegex.exec(content)) !== null) {
      const formTag = formMatch[1];
      const formContent = formMatch[2];

      const actionMatch = formTag.match(/action=["']([^"']*)["']/);
      const methodMatch = formTag.match(/method=["']([^"']*)["']/);
      const idMatch = formTag.match(/id=["']([^"']*)["']/);

      let action = actionMatch ? actionMatch[1] : '';
      if (action && !action.startsWith('http')) {
        try { action = new URL(action, baseUrl).href; } catch { action = ''; }
      }

      const inputs = [];
      const inputRegex = /<(?:input|button|select|textarea)([^>]*)>/gi;
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formContent)) !== null) {
        const tag = inputMatch[0];
        const attrs = inputMatch[1];
        const type = (attrs.match(/type=["']([^"']*)["']/) || [])[1] || '';
        const name = (attrs.match(/name=["']([^"']*)["']/) || [])[1] || '';
        const value = (attrs.match(/value=["']([^"']*)["']/) || [])[1] || '';
        const id = (attrs.match(/id=["']([^"']*)["']/) || [])[1] || '';
        const placeholder = (attrs.match(/placeholder=["']([^"']*)["']/) || [])[1] || '';
        inputs.push({ type, name, value, id, placeholder, tag: tag.startsWith('<input') ? 'input' : tag.startsWith('<button') ? 'button' : tag.startsWith('<select') ? 'select' : 'textarea' });
      }

      const usernameField = inputs.find((i) =>
        i.type === 'email' || i.name.match(/email|user|login|username/i) || i.id.match(/email|user|login|username/i) || i.placeholder.match(/email|user|login|username/i)
      ) || inputs.find((i) => i.type === 'text' && (i.name.includes('email') || i.name.includes('user') || i.name.includes('login') || i.name.includes('name')))
      || inputs.find((i) => i.type === 'text' || i.type === 'email');

      const passwordField = inputs.find((i) =>
        i.type === 'password'
      ) || inputs.find((i) => i.name.match(/pass|pwd|secret/i) || i.id.match(/pass|pwd|secret/i));

      const rememberMe = inputs.find((i) =>
        i.type === 'checkbox' && (i.name.match(/remember|keep|stay/i) || i.id.match(/remember|keep|stay/i) || i.value === '1')
      ) || inputs.find((i) => i.type === 'checkbox' && i.name.toLowerCase().includes('remember'));

      const extraFields = inputs.filter((i) =>
        i !== usernameField && i !== passwordField && i !== rememberMe && i.type !== 'submit' && i.type !== 'button' && i.type !== 'hidden'
      );

      if (usernameField && passwordField) {
        const loginForm = {
          action: action || baseUrl,
          method: methodMatch ? methodMatch[1].toUpperCase() : 'POST',
          id: idMatch ? idMatch[1] : '',
          usernameField: usernameField ? { name: usernameField.name, type: usernameField.type, id: usernameField.id, placeholder: usernameField.placeholder } : null,
          passwordField: passwordField ? { name: passwordField.name, type: passwordField.type, id: passwordField.id } : null,
          rememberMe: rememberMe ? { name: rememberMe.name, value: rememberMe.value } : null,
          extraFields,
        };
        return loginForm;
      }
    }
    return null;
  }

  /**
   * Analyzes cookies from response headers
   * @param {Object} headers
   * @returns {CookieAnalysis[]}
   */
  analyzeCookies(headers) {
    const cookies = [];
    const setCookieHeader = headers['set-cookie'];
    if (!setCookieHeader) return cookies;

    const cookieStrings = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
    for (const cookieStr of cookieStrings) {
      const parts = cookieStr.split(';').map((p) => p.trim());
      const nameValue = parts[0].split('=');
      const name = nameValue[0];
      const value = nameValue.slice(1).join('=');

      const cookie = {
        name,
        value: value.length > 50 ? value.slice(0, 50) + '...' : value,
        httpOnly: false,
        secure: false,
        sameSite: 'None',
        domain: '',
        path: '',
        expires: null,
        maxAge: null,
        sessionCookie: true,
        rawAttributes: {},
      };

      for (let i = 1; i < parts.length; i++) {
        const attrParts = parts[i].split('=');
        const attrName = attrParts[0].toLowerCase();
        const attrValue = attrParts.slice(1).join('=');

        switch (attrName) {
          case 'httponly':
            cookie.httpOnly = true;
            break;
          case 'secure':
            cookie.secure = true;
            break;
          case 'samesite':
            cookie.sameSite = attrValue || 'None';
            break;
          case 'domain':
            cookie.domain = attrValue;
            break;
          case 'path':
            cookie.path = attrValue;
            break;
          case 'expires':
            cookie.expires = attrValue;
            cookie.sessionCookie = false;
            break;
          case 'max-age':
            cookie.maxAge = parseInt(attrValue, 10);
            cookie.sessionCookie = false;
            break;
          default:
            cookie.rawAttributes[attrName] = attrValue;
        }
      }
      cookies.push(cookie);
    }
    return cookies;
  }

  /**
   * Decodes a JWT token without verification
   * @param {string} token
   * @returns {JWTDecoded|null}
   */
  decodeJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const headerRaw = Buffer.from(parts[0], 'base64url').toString('utf-8');
      const payloadRaw = Buffer.from(parts[1], 'base64url').toString('utf-8');
      let header, payload;
      try {
        header = JSON.parse(headerRaw);
      } catch {
        header = { raw: headerRaw };
      }
      try {
        payload = JSON.parse(payloadRaw);
      } catch {
        payload = { raw: payloadRaw };
      }

      return {
        header,
        payload,
        signature: parts[2].slice(0, 30) + '...',
        algorithm: header.alg || 'unknown',
        issuer: payload.iss || null,
        subject: payload.sub || null,
        audience: payload.aud || null,
        issuedAt: payload.iat || null,
        expiration: payload.exp || null,
        expired: payload.exp ? (Date.now() / 1000) > payload.exp : false,
        jwtId: payload.jti || null,
        notBefore: payload.nbf || null,
        roles: payload.roles || payload.role || null,
        scopes: payload.scopes || payload.scope || null,
        email: payload.email || null,
        username: payload.username || payload.preferred_username || null,
        customClaims: Object.keys(payload).filter((k) => !['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'nbf', 'roles', 'role', 'scopes', 'scope', 'email', 'username', 'preferred_username'].includes(k)),
      };
    } catch {
      return null;
    }
  }

  /**
   * Tests common auth bypass headers
   * @param {string} targetUrl
   * @returns {Promise<AuthTestResult[]>}
   */
  async testAuthBypassHeaders(targetUrl) {
    const results = [];
    const bypassHeaders = [
      { header: 'X-Forwarded-For', value: '127.0.0.1' },
      { header: 'X-Forwarded-For', value: 'localhost' },
      { header: 'X-Forwarded-For', value: '0.0.0.0' },
      { header: 'X-Real-IP', value: '127.0.0.1' },
      { header: 'X-Real-IP', value: 'localhost' },
      { header: 'X-Originating-IP', value: '127.0.0.1' },
      { header: 'X-Remote-IP', value: '127.0.0.1' },
      { header: 'X-Client-IP', value: '127.0.0.1' },
      { header: 'X-Host', value: 'localhost' },
      { header: 'X-Forwarded-Host', value: 'localhost' },
      { header: 'X-Custom-IP-Authorization', value: '127.0.0.1' },
      { header: 'X-Forwarded-For', value: '10.0.0.1' },
      { header: 'X-Real-IP', value: '10.0.0.1' },
      { header: 'X-Originating-IP', value: '10.0.0.1' },
      { header: 'X-Remote-IP', value: '10.0.0.1' },
      { header: 'X-Client-IP', value: '10.0.0.1' },
      { header: 'Forwarded', value: 'for=127.0.0.1;by=127.0.0.1;host=localhost' },
      { header: 'Forwarded', value: 'for=10.0.0.1;by=10.0.0.1;host=internal' },
      { header: 'X-Original-URL', value: '/admin' },
      { header: 'X-Rewrite-URL', value: '/admin' },
      { header: 'X-Original-URL', value: '/api/' },
      { header: 'X-Rewrite-URL', value: '/api/' },
    ];

    const baseline = await this.fetchUrl(targetUrl, 'GET');
    this.log(`Baseline response: ${baseline.status} (${baseline.body.length} bytes)`);

    for (const { header, value } of bypassHeaders) {
      try {
        const result = await this.fetchUrl(targetUrl, 'GET', null, { [header]: value });
        const bypassed = result.status !== baseline.status || result.body.length !== baseline.body.length;

        results.push({
          test: `Header: ${header}: ${value}`,
          endpoint: targetUrl,
          method: 'GET',
          status: result.status,
          headers: { [header]: value },
          bodySize: result.body.length,
          bypassed,
          reason: bypassed ? `Status changed from ${baseline.status} to ${result.status}, body size from ${baseline.body.length} to ${result.body.length}` : null,
        });

        if (bypassed) {
          this.log(`Bypass detected: ${header}: ${value} → ${result.status} (${result.body.length} bytes)`, 'warn');
        }

        await new Promise((r) => setTimeout(r, 100));
      } catch (err) {
        results.push({
          test: `Header: ${header}: ${value}`,
          endpoint: targetUrl,
          method: 'GET',
          status: 0,
          headers: {},
          bodySize: 0,
          bypassed: false,
          reason: `Error: ${err.message}`,
        });
      }
    }
    return results;
  }

  /**
   * Tests HTTP verb tampering
   * @param {string} targetUrl
   * @returns {Promise<AuthTestResult[]>}
   */
  async testVerbTampering(targetUrl) {
    const results = [];
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];

    const baseline = await this.fetchUrl(targetUrl, 'GET');
    this.log(`Baseline GET: ${baseline.status} (${baseline.body.length} bytes)`);

    for (const method of methods) {
      try {
        const result = await this.fetchUrl(targetUrl, method, method === 'POST' || method === 'PUT' || method === 'PATCH' ? '' : null);
        const bypassed = result.status !== baseline.status || (result.body.length !== baseline.body.length && result.body.length > 0);

        results.push({
          test: `Verb tampering: ${method}`,
          endpoint: targetUrl,
          method,
          status: result.status,
          headers: { 'content-type': result.headers['content-type'] || '', 'content-length': result.headers['content-length'] || '' },
          bodySize: result.body.length,
          bypassed,
          reason: bypassed ? `Status changed from ${baseline.status} to ${result.status}, body size from ${baseline.body.length} to ${result.body.length}` : null,
        });

        if (bypassed) {
          this.log(`Verb tampering detected: ${method} → ${result.status} (${result.body.length} bytes)`, 'warn');
        }

        await new Promise((r) => setTimeout(r, 50));
      } catch (err) {
        results.push({
          test: `Verb tampering: ${method}`,
          endpoint: targetUrl,
          method,
          status: 0,
          headers: {},
          bodySize: 0,
          bypassed: false,
          reason: `Error: ${err.message}`,
        });
      }
    }
    return results;
  }

  /**
   * Attempts login with given credentials
   * @param {string} loginUrl
   * @param {{username: string, password: string, usernameField?: string, passwordField?: string, extraFields?: Object}} credentials
   * @param {string} [method='POST']
   * @returns {Promise<{success: boolean, status: number, headers: Object, body: string, cookies: CookieAnalysis[], loginForm: LoginForm|null, elapsed: number}>}
   */
  async testLogin(loginUrl, credentials, method = 'POST') {
    this.log(`Testing login at ${loginUrl} with user: ${credentials.username}`);

    const pageResponse = await this.fetchUrl(loginUrl, 'GET');
    const loginForm = this.detectLoginForm(pageResponse.body, loginUrl);

    if (!loginForm) {
      this.log('No login form detected on page', 'warn');
    }

    const bodyParts = [];
    if (loginForm) {
      const userFieldName = credentials.usernameField || loginForm.usernameField.name;
      const passFieldName = credentials.passwordField || loginForm.passwordField.name;
      bodyParts.push(`${encodeURIComponent(userFieldName)}=${encodeURIComponent(credentials.username)}`);
      bodyParts.push(`${encodeURIComponent(passFieldName)}=${encodeURIComponent(credentials.password)}`);
      if (credentials.extraFields) {
        for (const [key, value] of Object.entries(credentials.extraFields)) {
          bodyParts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
        }
      }
    } else {
      bodyParts.push(`username=${encodeURIComponent(credentials.username)}`);
      bodyParts.push(`password=${encodeURIComponent(credentials.password)}`);
    }

    const body = bodyParts.join('&');
    const contentType = loginForm && loginForm.enctype === 'multipart/form-data' ? 'multipart/form-data' : 'application/x-www-form-urlencoded';

    const result = await this.fetchUrl(
      loginForm && loginForm.action ? loginForm.action : loginUrl,
      loginForm ? loginForm.method : method,
      body,
      {
        'Content-Type': contentType,
        'Content-Length': Buffer.byteLength(body).toString(),
      }
    );

    const cookies = this.analyzeCookies(result.headers);
    this.cookies.push(...cookies);

    let jwtDecoded = null;
    const jwtMatch = result.body.match(/eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/);
    if (jwtMatch) {
      jwtDecoded = this.decodeJWT(jwtMatch[0]);
      if (jwtDecoded) {
        this.jwtTokens.push({ source: loginUrl, token: jwtMatch[0], decoded: jwtDecoded });
      }
    }

    const cookieHeader = result.headers['set-cookie'] || '';
    const authHeader = result.headers['authorization'] || '';
    const success = result.status === 302 || result.status === 200 || (result.status < 400 && !result.body.includes('invalid') && !result.body.includes('error') && !result.body.includes('incorrect'));

    return {
      success,
      status: result.status,
      headers: result.headers,
      body: result.body.slice(0, 500),
      cookies,
      loginForm,
      jwtDecoded,
      hasAuthCookie: Array.isArray(cookieHeader) ? cookieHeader.length > 0 : !!cookieHeader,
      hasAuthHeader: !!authHeader,
      elapsed: result.elapsed,
    };
  }

  /**
   * Performs full JWT analysis on a token
   * @param {string} token
   * @returns {Object}
   */
  analyzeJWT(token) {
    const decoded = this.decodeJWT(token);
    if (!decoded) {
      return { valid: false, error: 'Invalid JWT format' };
    }

    const findings = [];

    if (decoded.algorithm === 'none') {
      findings.push({ severity: 'CRITICAL', issue: 'JWT uses "none" algorithm - server may accept unsigned tokens' });
    }

    if (!decoded.algorithm || decoded.algorithm === 'none') {
      findings.push({ severity: 'HIGH', issue: 'No signing algorithm specified' });
    }

    if (decoded.header.alg && decoded.header.alg.toLowerCase() === 'hs256' && decoded.payload) {
      findings.push({ severity: 'INFO', issue: 'Uses symmetric HMAC - verify secret strength' });
    }

    if (decoded.expired) {
      findings.push({ severity: 'INFO', issue: `Token expired at ${new Date(decoded.expiration * 1000).toISOString()}` });
    }

    if (!decoded.expiration) {
      findings.push({ severity: 'MEDIUM', issue: 'Token has no expiration claim (exp)' });
    } else {
      const remaining = decoded.expiration - (Date.now() / 1000);
      if (remaining > 86400 * 30) {
        findings.push({ severity: 'MEDIUM', issue: `Token has long expiry: ${Math.round(remaining / 86400)} days` });
      }
    }

    if (!decoded.issuer) {
      findings.push({ severity: 'LOW', issue: 'Token has no issuer claim (iss)' });
    }

    if (!decoded.audience) {
      findings.push({ severity: 'LOW', issue: 'Token has no audience claim (aud)' });
    }

    if (decoded.issuedAt && decoded.expiration && (decoded.expiration - decoded.issuedAt) > 86400 * 7) {
      findings.push({ severity: 'LOW', issue: `Token valid for ${Math.round((decoded.expiration - decoded.issuedAt) / 86400)} days` });
    }

    const kid = decoded.header.kid;
    if (kid) {
      findings.push({ severity: 'INFO', issue: `Token has kid header: ${kid} - verify no path traversal in key resolution` });
      if (kid.includes('/') || kid.includes('..')) {
        findings.push({ severity: 'HIGH', issue: 'Kid header contains path traversal characters - potential CVE-2018-0114' });
      }
    }

    if (decoded.header.jku) {
      findings.push({ severity: 'MEDIUM', issue: `Token has jku header: ${decoded.header.jku} - verify URL is trusted` });
    }

    if (decoded.header.jwk) {
      findings.push({ severity: 'HIGH', issue: 'Token embeds jwk header - potential JWK injection if server trusts embedded keys' });
    }

    if (decoded.header.typ && decoded.header.typ.toLowerCase() !== 'jwt') {
      findings.push({ severity: 'LOW', issue: `Unusual token type: ${decoded.header.typ}` });
    }

    const algorithmConfusion = ['RS256', 'RS384', 'RS512'].includes(decoded.algorithm) || ['ES256', 'ES384', 'ES512'].includes(decoded.algorithm);
    if (algorithmConfusion && decoded.header.alg) {
      findings.push({ severity: 'INFO', issue: `Uses asymmetric algorithm ${decoded.algorithm} - test algorithm confusion with HS256` });
    }

    const sensitiveClaims = ['role', 'roles', 'admin', 'is_admin', 'isAdmin', 'permissions', 'groups', 'scope', 'scopes'];
    for (const claim of sensitiveClaims) {
      if (decoded.payload[claim] !== undefined) {
        const val = typeof decoded.payload[claim] === 'object' ? JSON.stringify(decoded.payload[claim]) : String(decoded.payload[claim]);
        findings.push({ severity: 'MEDIUM', issue: `Contains authorization claim: ${claim}=${val}` });
      }
    }

    return {
      valid: true,
      decoded,
      findings,
      warningCount: findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH').length,
      infoCount: findings.filter((f) => f.severity === 'MEDIUM' || f.severity === 'LOW').length,
    };
  }

  /**
   * Tests for common auth-related endpoints
   * @param {string} baseUrl
   * @returns {Promise<Array<{path: string, status: number, method: string}>>}
   */
  async discoverAuthEndpoints(baseUrl) {
    const endpoints = [
      { path: '/login', methods: ['GET', 'POST'] },
      { path: '/signin', methods: ['GET', 'POST'] },
      { path: '/signup', methods: ['GET', 'POST'] },
      { path: '/register', methods: ['GET', 'POST'] },
      { path: '/logout', methods: ['GET', 'POST'] },
      { path: '/signout', methods: ['GET', 'POST'] },
      { path: '/forgot-password', methods: ['GET', 'POST'] },
      { path: '/reset-password', methods: ['GET', 'POST'] },
      { path: '/change-password', methods: ['GET', 'POST'] },
      { path: '/auth/login', methods: ['GET', 'POST'] },
      { path: '/auth/register', methods: ['GET', 'POST'] },
      { path: '/auth/logout', methods: ['GET', 'POST'] },
      { path: '/auth/forgot', methods: ['GET', 'POST'] },
      { path: '/auth/reset', methods: ['GET', 'POST'] },
      { path: '/auth/change-password', methods: ['GET', 'POST'] },
      { path: '/api/auth/login', methods: ['POST'] },
      { path: '/api/auth/register', methods: ['POST'] },
      { path: '/api/auth/logout', methods: ['POST'] },
      { path: '/api/auth/refresh', methods: ['POST'] },
      { path: '/api/auth/verify', methods: ['POST'] },
      { path: '/oauth/authorize', methods: ['GET', 'POST'] },
      { path: '/oauth/token', methods: ['POST'] },
      { path: '/oauth/revoke', methods: ['POST'] },
      { path: '/oauth/logout', methods: ['GET', 'POST'] },
      { path: '/saml/login', methods: ['GET', 'POST'] },
      { path: '/saml/acs', methods: ['POST'] },
      { path: '/saml/slo', methods: ['GET', 'POST'] },
      { path: '/saml/metadata', methods: ['GET'] },
      { path: '/mfa', methods: ['GET', 'POST'] },
      { path: '/mfa/setup', methods: ['GET', 'POST'] },
      { path: '/mfa/verify', methods: ['POST'] },
      { path: '/2fa', methods: ['GET', 'POST'] },
      { path: '/2fa/verify', methods: ['POST'] },
      { path: '/.well-known/openid-configuration', methods: ['GET'] },
      { path: '/.well-known/oauth-authorization-server', methods: ['GET'] },
    ];
    const results = [];
    for (const { path: epPath, methods } of endpoints) {
      const fullUrl = `${baseUrl.replace(/\/+$/, '')}${epPath}`;
      for (const method of methods) {
        try {
          const result = await this.fetchUrl(fullUrl, method);
          if (result.status !== 404) {
            results.push({ path: epPath, method, status: result.status, bodySize: result.body.length });
            this.log(`Found auth endpoint: ${method} ${fullUrl} → ${result.status}`);
          }
        } catch { }
      }
    }
    return results;
  }

  /**
   * Generates a summary report
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(metadata = {}) {
    const secureCookies = this.cookies.filter((c) => c.secure);
    const httpOnlyCookies = this.cookies.filter((c) => c.httpOnly);
    const sessionCookies = this.cookies.filter((c) => c.sessionCookie);
    const laxCookies = this.cookies.filter((c) => c.sameSite !== 'Strict' && c.sameSite !== 'Lax');

    const bypassResults = this.results.filter((r) => r.bypassed);
    const verbResults = this.results.filter((r) => r.test.startsWith('Verb tampering'));
    const headerResults = this.results.filter((r) => r.test.startsWith('Header:'));

    const jwtAnalysis = this.jwtTokens.length > 0 ? this.jwtTokens.map((j) => ({
      source: j.source,
      algorithm: j.decoded.algorithm,
      issuer: j.decoded.issuer,
      subject: j.decoded.subject,
      expired: j.decoded.expired,
      expiration: j.decoded.expiration ? new Date(j.decoded.expiration * 1000).toISOString() : null,
    })) : [];

    return {
      metadata: {
        ...metadata,
        generatedAt: new Date().toISOString(),
      },
      summary: {
        cookiesFound: this.cookies.length,
        cookiesSecure: secureCookies.length,
        cookiesHttpOnly: httpOnlyCookies.length,
        cookiesSessionOnly: sessionCookies.length,
        cookiesMissingSameSite: laxCookies.length,
        jwtTokensFound: this.jwtTokens.length,
        bypassTestsRun: headerResults.length,
        bypassesDetected: bypassResults.length,
        verbTamperingTestsRun: verbResults.length,
      },
      cookies: this.cookies,
      jwtTokens: jwtAnalysis,
      results: this.results.filter((r) => r.bypassed),
      allResults: this.results,
    };
  }

  /**
   * Runs full auth testing pipeline
   * @param {AuthTesterOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const startTime = Date.now();
    if (options.target && typeof options.target === 'string') {
      if (options.target.trim().length === 0) throw new Error('Target must not be empty');
      if (options.target.length > MAX_URL_LENGTH) throw new Error(`Target URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
    }
    if (options.loginUrl && typeof options.loginUrl === 'string') {
      if (options.loginUrl.trim().length === 0) throw new Error('Login URL must not be empty');
      if (options.loginUrl.length > MAX_URL_LENGTH) throw new Error(`Login URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
    }
    let credentials = null;
    let jwtAnalysis = null;
    let loginResult = null;
    let authEndpoints = [];

    if (options.target) {
      this.log(`Testing auth for target: ${options.target}`);

      authEndpoints = await this.discoverAuthEndpoints(options.target);
      this.log(`Discovered ${authEndpoints.length} auth endpoints`);
    }

    if (options.analyzeJwt && options.credentials) {
      try {
        let jwtToken = '';
        if (typeof options.credentials === 'string' && fs.existsSync(options.credentials)) {
          const resolvedPath = path.resolve(options.credentials);
          if (!resolvedPath.startsWith(process.cwd())) {
            throw new Error('Path traversal detected: ' + options.credentials);
          }
          const st = fs.statSync(options.credentials);
          if (st.size > MAX_FILE_SIZE) {
            throw new Error(`File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB (${st.size} bytes)`);
          }
          jwtToken = fs.readFileSync(options.credentials, 'utf-8').trim();
        } else {
          jwtToken = options.credentials;
        }
        jwtAnalysis = this.analyzeJWT(jwtToken);
        this.log(`JWT analysis: ${jwtAnalysis.warningCount} warnings, ${jwtAnalysis.infoCount} infos`);
      } catch (err) {
        this.log(`Failed to analyze JWT: ${err.message}`, 'error');
      }
    }

    if (options.credentials && options.loginUrl) {
      try {
        let creds;
        if (typeof options.credentials === 'string' && fs.existsSync(options.credentials)) {
          const resolvedPath = path.resolve(options.credentials);
          if (!resolvedPath.startsWith(process.cwd())) {
            throw new Error('Path traversal detected: ' + options.credentials);
          }
          const st = fs.statSync(options.credentials);
          if (st.size > MAX_FILE_SIZE) {
            throw new Error(`File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB (${st.size} bytes)`);
          }
          creds = JSON.parse(fs.readFileSync(options.credentials, 'utf-8'));
        } else {
          creds = JSON.parse(options.credentials);
        }
        credentials = creds;
        loginResult = await this.testLogin(options.loginUrl, creds, options.method || 'POST');
        this.log(`Login result: ${loginResult.success ? 'SUCCESS' : 'FAILURE'} (${loginResult.status})`);

        if (loginResult.jwtDecoded && this.analyzeJwt) {
          jwtAnalysis = this.analyzeJWT(loginResult.jwtDecoded);
          this.log(`JWT analysis: ${jwtAnalysis.warningCount} warnings, ${jwtAnalysis.infoCount} infos`);
        }
      } catch (err) {
        this.log(`Login test failed: ${err.message}`, 'error');
      }
    }

    if (options.testBypasses && options.target) {
      this.log('Testing auth bypass headers...');
      const headerResults = await this.testAuthBypassHeaders(options.target);
      this.results.push(...headerResults);

      this.log('Testing verb tampering...');
      const verbResults = await this.testVerbTampering(options.target);
      this.results.push(...verbResults);

      const bypassCount = headerResults.filter((r) => r.bypassed).length;
      const verbCount = verbResults.filter((r) => r.bypassed).length;
      this.log(`Bypass tests complete: ${bypassCount} header bypasses, ${verbCount} verb tampering`);
    }

    const report = this.generateReport({
      target: options.target,
      loginUrl: options.loginUrl,
      loginAttempted: !!loginResult,
      loginSuccessful: loginResult ? loginResult.success : false,
      loginStatus: loginResult ? loginResult.status : null,
      authEndpointsDiscovered: authEndpoints.length,
      elapsed: Date.now() - startTime,
    });

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
 * Parses command line arguments
 * @returns {AuthTesterOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { silent: false, testBypasses: false, analyzeJwt: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--target':
        options.target = args[++i];
        break;
      case '--login-url':
        options.loginUrl = args[++i];
        break;
      case '--credentials':
        options.credentials = args[++i];
        break;
      case '--method':
        options.method = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--test-bypasses':
        options.testBypasses = true;
        break;
      case '--analyze-jwt':
        options.analyzeJwt = true;
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
        break;
    }
  }
  if (!options.target && !options.credentials && !options.analyzeJwt) {
    process.stderr.write('Error: --target, --credentials (for JWT analysis), or --analyze-jwt is required\n');
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
Authentication Testing Tool - auth-tester.js
Tests authentication mechanisms, analyzes JWT tokens, and detects auth bypasses.

USAGE:
  node auth-tester.js --target <url> [options]
  node auth-tester.js --analyze-jwt --credentials <token-or-file>
  node auth-tester.js --login-url <url> --credentials <json-or-file> [options]

OPTIONS:
  --target <url>           Target base URL for discovery and bypass tests
  --login-url <url>        Login page URL for credential testing
  --credentials <value>    Credentials JSON (inline or file path) or JWT string
  --method <method>        HTTP method for login (default: POST)
  --output <path>          Write results to JSON file
  --test-bypasses          Run auth bypass header and verb tampering tests
  --analyze-jwt            Perform detailed JWT analysis
  --silent                 Suppress verbose output
  --timeout <ms>           Request timeout in milliseconds (default: 15000)
  --help, -h               Show this help message

EXAMPLES:
  node auth-tester.js --target https://example.com --test-bypasses
  node auth-tester.js --analyze-jwt --credentials "eyJhbGciOiJIUzI1NiJ9..."
  node auth-tester.js --login-url https://example.com/login --credentials '{"username":"test@test.com","password":"test123"}'
  node auth-tester.js --target https://example.com --test-bypasses --output auth-report.json
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const tester = new AuthTester(options);
    const report = await tester.run(options);
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

module.exports = { AuthTester };
