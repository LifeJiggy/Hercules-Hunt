#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_URL_LENGTH = 8192;
const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * @typedef {Object} ParameterInfo
 * @property {string} name - Parameter name
 * @property {string} source - Where it was found (query, body, header, cookie, path)
 * @property {string} sample - Sample value
 * @property {string} method - HTTP method used
 * @property {boolean} required - Whether the parameter appears required
 * @property {string} type - Inferred data type
 */

/**
 * @typedef {Object} ExtractParametersOptions
 * @property {string} url - Target URL
 * @property {string} [file] - Local file to analyze
 * @property {string} [method='GET'] - HTTP method
 * @property {string} [body] - Request body
 * @property {string} [headers] - Custom headers
 * @property {string} [output] - Output file path
 * @property {boolean} [fuzz=false] - Fuzz missing parameters
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class ParameterExtractor {
  constructor(options = {}) {
    this.url = options.url || '';
    this.file = options.file || '';
    this.method = (options.method || 'GET').toUpperCase();
    this.body = options.body || '';
    this.headerStr = options.headers || '';
    this.fuzzEnabled = options.fuzz || false;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 10000;
    this.userAgent = 'Hercules-Hunt-Parameter-Extractor/1.0';
    this.parameters = [];
    this.sensitiveNames = [
      'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey', 'api-key',
      'auth', 'authorization', 'jwt', 'access_token', 'refresh_token',
      'session', 'sessionid', 'sid', 'csrf', 'csrf_token', 'csrfmiddlewaretoken',
      'credit', 'cc', 'card', 'cvv', 'cvc', 'pin', 'ssn', 'social',
      'key', 'private', 'private_key', 'ssh', 'cert', 'certificate',
      'aws', 's3', 'bucket', 'firebase', 'stripe', 'slack', 'github',
      'admin', 'root', 'user', 'username', 'email', 'phone', 'phone_number',
    ];
    this.commonParamNames = [
      'id', 'user_id', 'userId', 'user-id', 'uid', 'uuid', 'guid',
      'token', 'page', 'limit', 'offset', 'count', 'skip', 'take',
      'sort', 'order', 'filter', 'q', 'query', 'search', 's',
      'name', 'title', 'slug', 'type', 'status', 'state', 'category',
      'email', 'username', 'password', 'role', 'group', 'permission',
      'url', 'redirect', 'return', 'next', 'callback', 'redirect_uri',
      'file', 'filename', 'path', 'dir', 'folder', 'upload',
      'action', 'method', 'format', 'ext', 'extension', 'version',
      'date', 'from', 'to', 'start', 'end', 'before', 'after',
      'debug', 'verbose', 'pretty', 'expand', 'include', 'embed',
      'fields', 'select', 'include', 'exclude', 'scope', 'lang',
      'config', 'setting', 'option', 'preference', 'mode', 'env',
      'locale', 'timezone', 'tz', 'country', 'region', 'langage',
      'callback', '_', 'r', 'ref', 'source', 'origin', 'host',
      'api_key', 'apikey', 'api-key', 'client_id', 'client_secret',
      'code', 'state', 'nonce', 'grant_type', 'response_type',
      'signature', 'hash', 'checksum', 'hmac', 'nonce',
      'width', 'height', 'size', 'quality', 'resolution', 'format',
    ];
    this.paramTypes = {
      'id': 'integer', 'user_id': 'integer', 'uid': 'integer', 'uuid': 'uuid',
      'page': 'integer', 'limit': 'integer', 'offset': 'integer', 'count': 'integer',
      'skip': 'integer', 'take': 'integer', 'age': 'integer', 'year': 'integer',
      'email': 'email', 'username': 'string', 'name': 'string', 'title': 'string',
      'q': 'string', 'query': 'string', 'search': 'string',
      'url': 'url', 'redirect': 'url', 'callback': 'url', 'redirect_uri': 'url',
      'token': 'token', 'api_key': 'token', 'apikey': 'token', 'secret': 'token',
      'password': 'password', 'passwd': 'password',
      'date': 'date', 'from': 'date', 'to': 'date', 'before': 'date', 'after': 'date',
      'sort': 'enum', 'order': 'enum', 'direction': 'enum',
      'format': 'enum', 'type': 'enum', 'status': 'enum', 'mode': 'enum',
      'file': 'file', 'filename': 'file', 'upload': 'file',
      'page': 'integer', 'size': 'integer', 'limit': 'integer',
      'debug': 'boolean', 'verbose': 'boolean', 'pretty': 'boolean',
      'include': 'array', 'exclude': 'array', 'fields': 'array', 'expand': 'array',
    };
    this.fuzzValues = {
      integer: ['0', '1', '-1', '999999', 'null', 'undefined', 'NaN'],
      string: ['test', 'admin', 'root', 'null', 'undefined', '*', '%00'],
      email: ['test@test.com', 'admin@test.com', 'test@example.com', 'none@none.com'],
      url: ['http://localhost', 'http://127.0.0.1', 'https://evil.com', 'file:///etc/passwd'],
      token: ['invalid', 'expired', 'null', 'none', 'test123'],
      password: ['password', 'admin', '123456', 'password123!'],
      boolean: ['true', 'false', '1', '0'],
      uuid: ['00000000-0000-0000-0000-000000000000', 'ffffffff-ffff-ffff-ffff-ffffffffffff'],
      array: ['a,b,c', '1,2,3', 'item1,item2'],
      file: ['../../../etc/passwd', 'test.png', 'shell.php', 'test.html'],
      enum: ['ASC', 'DESC', 'asc', 'desc', 'default', 'random'],
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
   * Sends HTTP request
   * @param {string} method
   * @param {string} url
   * @param {Object} [extraOpts={}]
   * @returns {Promise<Object>}
   */
  async request(method, url, extraOpts = {}) {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const headers = {
      'User-Agent': this.userAgent,
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      ...extraOpts.headers,
    };
    const bodyData = extraOpts.body || null;
    if (bodyData && !headers['Content-Type']) {
      headers['Content-Type'] = typeof bodyData === 'object' ? 'application/json' : 'application/x-www-form-urlencoded';
    }
    return new Promise((resolve) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers,
        timeout: extraOpts.timeout || this.timeout,
        rejectUnauthorized: false,
      };
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
          });
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', bodyLength: 0, error: 'timeout' }); });
      req.on('error', (e) => resolve({ status: 0, headers: {}, body: '', bodyLength: 0, error: e.message }));
      if (bodyData) {
        req.write(typeof bodyData === 'object' ? JSON.stringify(bodyData) : bodyData);
      }
      req.end();
    });
  }

  /**
   * Extracts parameters from URL query string
   * @param {string} urlStr
   * @returns {ParameterInfo[]}
   */
  extractFromQuery(urlStr) {
    const params = [];
    try {
      const parsed = new URL(urlStr);
      for (const [key, value] of parsed.searchParams.entries()) {
        params.push({
          name: key,
          source: 'query',
          sample: value,
          method: this.method,
          required: false,
          type: this.inferType(key, value),
          sensitive: this.isSensitive(key),
        });
      }
    } catch { /* ignore */ }
    return params;
  }

  /**
   * Extracts parameters from path segments
   * @param {string} urlStr
   * @returns {ParameterInfo[]}
   */
  extractFromPath(urlStr) {
    const params = [];
    try {
      const parsed = new URL(urlStr);
      const segments = parsed.pathname.split('/').filter(Boolean);
      for (let i = 0; i < segments.length; i++) {
        const seg = segments[i];
        if (/^\d+$/.test(seg)) {
          params.push({ name: `path_param_${i}`, source: 'path', sample: seg, method: this.method, required: true, type: 'integer', sensitive: false });
        } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) {
          params.push({ name: `path_uuid_${i}`, source: 'path', sample: seg, method: this.method, required: true, type: 'uuid', sensitive: false });
        } else if (/^[A-Za-z0-9_-]{20,}$/.test(seg)) {
          params.push({ name: `path_token_${i}`, source: 'path', sample: seg, method: this.method, required: true, type: 'token', sensitive: true });
        }
      }
    } catch { /* ignore */ }
    return params;
  }

  /**
   * Extracts parameters from request body
   * @param {string} bodyStr
   * @param {string} contentType
   * @returns {ParameterInfo[]}
   */
  extractFromBody(bodyStr, contentType = '') {
    const params = [];
    if (!bodyStr) return params;
    if (contentType.includes('json') || bodyStr.trim().startsWith('{') || bodyStr.trim().startsWith('[')) {
      try {
        const json = JSON.parse(bodyStr);
        this.flattenJson(json, '', params);
      } catch {
        this.log('Body is not valid JSON, trying form-encoded', 'debug');
      }
    }
    if (contentType.includes('x-www-form-urlencoded') || (bodyStr.includes('=') && !bodyStr.trim().startsWith('{'))) {
      try {
        const sp = new URLSearchParams(bodyStr);
        for (const [key, value] of sp.entries()) {
          params.push({
            name: key,
            source: 'body_form',
            sample: value,
            method: this.method,
            required: false,
            type: this.inferType(key, value),
            sensitive: this.isSensitive(key),
          });
        }
      } catch { /* ignore */ }
    }
    return params;
  }

  /**
   * Recursively flattens JSON to parameter list
   * @param {*} obj
   * @param {string} prefix
   * @param {ParameterInfo[]} params
   */
  flattenJson(obj, prefix, params) {
    if (obj === null || obj === undefined) return;
    if (typeof obj !== 'object') {
      params.push({
        name: prefix || 'value',
        source: 'body_json',
        sample: String(obj).slice(0, 100),
        method: this.method,
        required: true,
        type: typeof obj,
        sensitive: this.isSensitive(prefix),
      });
      return;
    }
    if (Array.isArray(obj)) {
      params.push({ name: prefix || 'array', source: 'body_json', sample: `[${obj.length} items]`, method: this.method, required: true, type: 'array', sensitive: false });
      if (obj.length > 0) {
        this.flattenJson(obj[0], `${prefix}[0]`, params);
      }
      return;
    }
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      if (value !== null && typeof value === 'object') {
        params.push({ name: fullKey, source: 'body_json', sample: Array.isArray(value) ? `[${value.length} items]` : '{...}', method: this.method, required: true, type: Array.isArray(value) ? 'array' : 'object', sensitive: this.isSensitive(fullKey) });
        this.flattenJson(value, fullKey, params);
      } else {
        params.push({
          name: fullKey,
          source: 'body_json',
          sample: value !== null && value !== undefined ? String(value).slice(0, 100) : 'null',
          method: this.method,
          required: true,
          type: value === null ? 'null' : typeof value,
          sensitive: this.isSensitive(fullKey),
        });
      }
    }
  }

  /**
   * Extracts parameters from HTTP headers
   * @param {string} headerStr
   * @returns {ParameterInfo[]}
   */
  extractFromHeaders(headerStr) {
    const params = [];
    if (!headerStr) return params;
    const lines = headerStr.split('\n');
    for (const line of lines) {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const name = line.slice(0, idx).trim();
        const value = line.slice(idx + 1).trim();
        if (name) {
          params.push({
            name,
            source: 'header',
            sample: value.slice(0, 100),
            method: this.method,
            required: false,
            type: 'string',
            sensitive: this.isSensitive(name),
          });
        }
      }
    }
    return params;
  }

  /**
   * Infers parameter type from name and sample value
   * @param {string} name
   * @param {string} value
   * @returns {string}
   */
  inferType(name, value) {
    const lower = name.toLowerCase().replace(/[_-]/g, '_');
    for (const [key, type] of Object.entries(this.paramTypes)) {
      if (lower === key || lower.endsWith(`_${key}`) || lower.startsWith(`${key}_`)) return type;
    }
    if (/^\d+$/.test(value)) return 'integer';
    if (/^\d+\.\d+$/.test(value)) return 'float';
    if (/^(true|false)$/i.test(value)) return 'boolean';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid';
    if (/^https?:\/\//.test(value)) return 'url';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return 'email';
    if (/^\d{4}-\d{2}-\d{2}/.test(value)) return 'date';
    if (/^eyJ/.test(value)) return 'jwt';
    if (value.length > 50) return 'text';
    return 'string';
  }

  /**
   * Checks if parameter name is sensitive
   * @param {string} name
   * @returns {boolean}
   */
  isSensitive(name) {
    const lower = name.toLowerCase().replace(/[_-]/g, '_');
    return this.sensitiveNames.some((s) => lower === s || lower.includes(s));
  }

  /**
   * Extracts parameters from a local file
   * @param {string} filePath
   * @returns {ParameterInfo[]}
   */
  extractFromFile(filePath) {
    if (!filePath || typeof filePath !== 'string') {
      throw new Error('Invalid file path: must be a non-empty string');
    }
    const resolvedPath = path.resolve(filePath);
    if (!resolvedPath.startsWith(process.cwd())) {
      throw new Error('Path traversal detected: ' + filePath);
    }
    if (!fs.existsSync(filePath)) {
      throw new Error(`File not found: ${filePath}`);
    }
    const st = fs.statSync(filePath);
    if (st.size > MAX_FILE_SIZE) {
      throw new Error(`File exceeds maximum size of ${MAX_FILE_SIZE / 1024 / 1024}MB (${st.size} bytes)`);
    }
    this.log(`Reading file: ${filePath}`);
    const content = fs.readFileSync(filePath, 'utf-8');
    const params = [];
    if (content.trim().startsWith('{') || content.trim().startsWith('[')) {
      try {
        this.flattenJson(JSON.parse(content), '', params);
        this.log(`Extracted ${params.length} parameters from JSON file`);
      } catch {
        this.log('File is not valid JSON, treating as URL-encoded', 'warn');
      }
    }
    if (content.includes('=')) {
      try {
        const sp = new URLSearchParams(content);
        for (const [key, value] of sp.entries()) {
          params.push({ name: key, source: 'file', sample: value, method: 'UNKNOWN', required: false, type: this.inferType(key, value), sensitive: this.isSensitive(key) });
        }
      } catch { /* ignore */ }
    }
    return params;
  }

  /**
   * Gets unique parameter names from all sources
   * @param {ParameterInfo[]} params
   * @returns {string[]}
   */
  getUniqueNames(params) {
    return [...new Set(params.map((p) => p.name))].sort();
  }

  /**
   * Fuzzes parameters by inferring type and testing common values
   * @param {ParameterInfo[]} params
   * @param {string} baseUrl
   * @returns {Promise<Array<{name: string, fuzzValue: string, status: number, type: string}>>}
   */
  async fuzzParameters(params, baseUrl) {
    const results = [];
    const uniqueNames = this.getUniqueNames(params);
    for (const name of uniqueNames) {
      const existing = params.find((p) => p.name === name);
      const type = existing ? existing.type : 'string';
      const fuzzValues = this.fuzzValues[type] || this.fuzzValues.string;
      for (const fuzzVal of fuzzValues.slice(0, 4)) {
        const testUrl = `${baseUrl}${baseUrl.includes('?') ? '&' : '?'}${encodeURIComponent(name)}=${encodeURIComponent(fuzzVal)}`;
        try {
          const res = await this.request('GET', testUrl);
          results.push({ name, fuzzValue: fuzzVal, status: res.status, type, size: res.bodyLength });
        } catch { results.push({ name, fuzzValue: fuzzVal, status: 0, type, error: true }); }
      }
    }
    return results;
  }

  /**
   * Analyzes parameter distribution
   * @param {ParameterInfo[]} params
   * @returns {Object}
   */
  analyzeParameters(params) {
    const bySource = {};
    const byType = {};
    const sensitive = [];
    for (const p of params) {
      if (!bySource[p.source]) bySource[p.source] = [];
      bySource[p.source].push(p);
      if (!byType[p.type]) byType[p.type] = [];
      byType[p.type].push(p);
      if (p.sensitive) sensitive.push(p);
    }
    const uniqueNames = this.getUniqueNames(params);
    return {
      total: params.length,
      unique: uniqueNames.length,
      bySource: Object.fromEntries(Object.entries(bySource).map(([k, v]) => [k, v.length])),
      byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length])),
      sensitiveCount: sensitive.length,
      sensitive,
    };
  }

  /**
   * Generates report
   * @param {ParameterInfo[]} params
   * @param {Object} fuzzResults
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(params, fuzzResults, metadata = {}) {
    const analysis = this.analyzeParameters(params);
    return {
      metadata: {
        tool: 'extract-parameters.js',
        timestamp: new Date().toISOString(),
        input: this.url || this.file || 'unknown',
        method: this.method,
        fuzzingPerformed: this.fuzzEnabled,
        ...metadata,
      },
      summary: {
        totalParameters: analysis.total,
        uniqueParameters: analysis.unique,
        bySource: analysis.bySource,
        byType: analysis.byType,
        sensitiveParameters: analysis.sensitiveCount,
      },
      parameters: params.sort((a, b) => a.name.localeCompare(b.name)),
      uniqueNames: this.getUniqueNames(params),
      sensitive: analysis.sensitive,
      fuzzing: fuzzResults || null,
    };
  }

  /**
   * Runs extraction pipeline
   * @param {ExtractParametersOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    if (options.url && typeof options.url === 'string') {
      if (options.url.trim().length === 0) throw new Error('URL must not be empty');
      if (options.url.length > MAX_URL_LENGTH) throw new Error(`URL exceeds maximum length of ${MAX_URL_LENGTH} characters`);
    }
    if (options.file && typeof options.file === 'string') {
      if (options.file.trim().length === 0) throw new Error('File path must not be empty');
    }
    let allParams = [];
    let fuzzResults = null;
    if (options.file) {
      allParams = this.extractFromFile(options.file);
    } else if (options.url) {
      this.url = options.url;
      this.method = (options.method || 'GET').toUpperCase();
      this.body = options.body || '';
      this.headerStr = options.headers || '';
      const queryParams = this.extractFromQuery(this.url);
      allParams.push(...queryParams);
      const pathParams = this.extractFromPath(this.url);
      allParams.push(...pathParams);
      if (this.body) {
        const bodyParams = this.extractFromBody(this.body);
        allParams.push(...bodyParams);
      }
      if (this.headerStr) {
        const headerParams = this.extractFromHeaders(this.headerStr);
        allParams.push(...headerParams);
      }
      try {
        const res = await this.request(this.method, this.url);
        const responseHeaders = res.headers;
        const cookieParams = [];
        if (responseHeaders['set-cookie']) {
          const cookies = Array.isArray(responseHeaders['set-cookie']) ? responseHeaders['set-cookie'] : [responseHeaders['set-cookie']];
          for (const c of cookies) {
            const name = c.split('=')[0].trim();
            if (name) {
              cookieParams.push({ name, source: 'cookie', sample: c.slice(0, 80), method: this.method, required: false, type: 'string', sensitive: this.isSensitive(name) });
            }
          }
        }
        allParams.push(...cookieParams);
        if (res.headers['content-type'] && res.headers['content-type'].includes('json')) {
          try {
            const jsonBody = JSON.parse(res.body);
            this.flattenJson(jsonBody, 'response.', allParams);
          } catch { /* ignore */ }
        }
        this.log(`Extracted ${allParams.length} parameters from URL: ${this.url}`);
        if (this.fuzzEnabled) {
          this.log('Fuzzing parameters...');
          const baseUrl = this.url.split('?')[0];
          fuzzResults = await this.fuzzParameters(allParams, baseUrl);
          this.log(`Fuzzing complete: ${fuzzResults.length} probe results`);
        }
      } catch (err) {
        this.log(`Failed to fetch URL: ${err.message}`, 'error');
      }
    } else {
      throw new Error('Either --url or --file is required');
    }
    const report = this.generateReport(allParams, fuzzResults);
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
 * @returns {ExtractParametersOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { method: 'GET', fuzz: false, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':
        options.url = args[++i];
        break;
      case '--file':
        options.file = args[++i];
        break;
      case '--method':
        options.method = args[++i].toUpperCase();
        break;
      case '--body':
        options.body = args[++i];
        break;
      case '--headers':
        options.headers = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--fuzz':
        options.fuzz = true;
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
        if (!options.url) options.url = args[i];
    }
  }
  if (!options.url && !options.file) {
    process.stderr.write('Error: --url or --file is required\n');
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
Parameter Extraction Tool - extract-parameters.js
Extracts parameters from URLs, request bodies, headers, and cookies.

USAGE:
  node extract-parameters.js --url <url> [options]
  node extract-parameters.js --file <json-or-form-file> [options]

OPTIONS:
  --url <url>          Target URL with query string
  --file <path>        JSON or URL-encoded file to parse
  --method <method>    HTTP method to use (default: GET)
  --body <body>        Request body for body parameter extraction
  --headers <str>      Custom headers to extract header params
  --output <path>      Write results to JSON file
  --fuzz               Enable parameter fuzzing
  --silent             Suppress verbose output
  --help, -h           Show this help message

FEATURES:
  - Query string parameter extraction
  - Path segment analysis (detects IDs, UUIDs, tokens)
  - JSON body parameter discovery (nested objects/flattened)
  - Form-encoded body parameter extraction
  - HTTP header parameter extraction
  - Cookie parameter extraction from Set-Cookie
  - Sensitive parameter detection (password, token, key, etc.)
  - Automatic type inference (integer, uuid, url, email, etc.)
  - Parameter fuzzing with type-aware values

EXAMPLES:
  node extract-parameters.js --url "https://api.example.com/users?id=123&name=test"
  node extract-parameters.js --url https://example.com/api/login --method POST --body '{"user":"admin","pass":"test"}'
  node extract-parameters.js --file parameters.json --output params.json
  node extract-parameters.js --url https://example.com --fuzz --silent > results.json
`;
  process.stderr.write(help);
}

/**
 * Main
 */
async function main() {
  try {
    const options = parseArgs();
    const extractor = new ParameterExtractor(options);
    const report = await extractor.run(options);
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

module.exports = { ParameterExtractor };
