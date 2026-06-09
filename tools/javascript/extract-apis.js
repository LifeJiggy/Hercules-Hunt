#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * @typedef {Object} ApiEndpoint
 * @property {string} url - The endpoint URL
 * @property {string[]} methods - Detected HTTP methods
 * @property {string} type - API type (rest, graphql, soap, websocket)
 * @property {number} statusCode - HTTP response status code
 * @property {string|null} authType - Detected authentication type
 * @property {Object} headers - Response headers
 */

/**
 * @typedef {Object} ExtractApisOptions
 * @property {string} [url] - Target URL to crawl
 * @property {string} [file] - Local file to analyze
 * @property {string} [output] - Output file path
 * @property {number} [depth=2] - Crawl depth
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class ApiExtractor {
  constructor(options = {}) {
    this.depth = options.depth || 2;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 15000;
    this.userAgent = 'Hercules-Hunt-API-Extractor/1.0';
    this.endpoints = new Map();
    this.visited = new Set();
    this.methodsProbed = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'];
    this.apiPatterns = [
      { regex: /\/api\/v?\d*[\w\-./]*/gi, type: 'rest' },
      { regex: /\/v\d+\/[\w\-./]*/gi, type: 'rest' },
      { regex: /\/rest\/[\w\-./]*/gi, type: 'rest' },
      { regex: /\/graphql[\w\-./]*/gi, type: 'graphql' },
      { regex: /\/soap\/[\w\-./]*/gi, type: 'soap' },
      { regex: /\/ws\/[\w\-./]*/gi, type: 'websocket' },
      { regex: /\/wss?:\/\//gi, type: 'websocket' },
      { regex: /\/oauth[\w\-./]*/gi, type: 'rest' },
      { regex: /\/callback[\w\-./]*/gi, type: 'rest' },
      { regex: /\/webhook[\w\-./]*/gi, type: 'rest' },
      { regex: /rpc\/json/gi, type: 'rpc' },
      { regex: /\/jsonrpc/gi, type: 'rpc' },
      { regex: /\/swagger[\w\-./]*/gi, type: 'rest' },
      { regex: /\/openapi[\w\-./]*/gi, type: 'rest' },
      { regex: /\/docs\/[\w\-./]*/gi, type: 'rest' },
      { regex: /\/v?\d+(?:\.\d+)?\/[\w\-./]*/gi, type: 'rest' },
      { regex: /\/trpc\/[\w\-./]*/gi, type: 'rpc' },
      { regex: /\/sse\/[\w\-./]*/gi, type: 'websocket' },
      { regex: /\/stream[\w\-./]*/gi, type: 'websocket' },
      { regex: /\/event[\w\-./]*/gi, type: 'websocket' },
      { regex: /\/pubsub[\w\-./]*/gi, type: 'websocket' },
      { regex: /\/subscribe[\w\-./]*/gi, type: 'websocket' },
    ];
    this.authPatterns = [
      { regex: /authorization:\s*bearer\s+/gi, name: 'Bearer Token' },
      { regex: /authorization:\s*basic\s+/gi, name: 'Basic Auth' },
      { regex: /authorization:\s*digest\s+/gi, name: 'Digest Auth' },
      { regex: /apikey[\w\-]*:/gi, name: 'API Key' },
      { regex: /x-api-key/gi, name: 'X-API-Key' },
      { regex: /x-auth-token/gi, name: 'X-Auth-Token' },
      { regex: /jwt[\w\-]*:/gi, name: 'JWT' },
      { regex: /token[\w\-]*:/gi, name: 'Token' },
      { regex: /session[\w\-]*:/gi, name: 'Session' },
      { regex: /cookie[\w\-]*:/gi, name: 'Cookie' },
    ];
  }

  /**
   * Logs message to stderr unless silent mode is active
   * @param {string} msg
   * @param {string} [level=info]
   */
  log(msg, level = 'info') {
    if (!this.silent) {
      process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
    }
  }

  /**
   * Fetches a URL and returns parsed response
   * @param {string} targetUrl
   * @returns {Promise<{status: number, headers: Object, body: string, contentType: string}>}
   */
  async fetchUrl(targetUrl) {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,*/*',
          'Accept-Language': 'en-US,en;q=0.9',
        },
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
            contentType: res.headers['content-type'] || '',
          });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout fetching ${targetUrl}`)); });
      req.on('error', (e) => reject(new Error(`Request error for ${targetUrl}: ${e.message}`)));
      req.end();
    });
  }

  /**
   * Probes a URL with a specific HTTP method
   * @param {string} url
   * @param {string} method
   * @returns {Promise<{status: number, headers: Object, body: string}>}
   */
  async probeMethod(url, method) {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    return new Promise((resolve) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers: {
          'User-Agent': this.userAgent,
          'Accept': '*/*',
          'Accept-Language': 'en-US,en;q=0.9',
        },
        timeout: this.timeout / 2,
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
            body: Buffer.concat(chunks).toString().slice(0, 1024),
            elapsed: Date.now() - start,
          });
        });
      });
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', elapsed: 0, error: 'timeout' }); });
      req.on('error', () => resolve({ status: 0, headers: {}, body: '', elapsed: 0, error: 'error' }));
      req.end();
    });
  }

  /**
   * Extracts API endpoints from content using regex patterns
   * @param {string} content
   * @param {string} [sourceUrl='']
   * @returns {Array<{url: string, type: string}>}
   */
  extractFromContent(content, sourceUrl = '') {
    const found = new Map();
    for (const { regex, type } of this.apiPatterns) {
      let match;
      while ((match = regex.exec(content)) !== null) {
        let ep = match[0].trim();
        if (ep.length < 3 || ep.startsWith('data:') || ep.startsWith('javascript:')) continue;
        if (!ep.startsWith('http')) {
          if (sourceUrl) {
            try {
              const base = new URL(sourceUrl);
              ep = ep.startsWith('/') ? `${base.origin}${ep}` : `${base.origin}/${ep}`;
            } catch { continue; }
          }
        }
        if (!found.has(ep)) {
          found.set(ep, { url: ep, type });
        }
      }
    }
    const extractPatterns = [
      /fetch\(["'`]([^"'`]+)["'`]/g,
      /axios\.(?:get|post|put|patch|delete|request)\(["'`]([^"'`]+)["'`]/g,
      /\$\.(?:get|post|ajax|put|delete)\(["'`]([^"'`]+)["'`]/g,
      /XMLHttpRequest\.open\(["'`][A-Z]+["'`],\s*["'`]([^"'`]+)["'`]/g,
      /url:\s*["'`]([^"'`]+)["'`]/g,
      /endpoint:\s*["'`]([^"'`]+)["'`]/g,
      /path:\s*["'`]([^"'`]+)["'`]/g,
      /route:\s*["'`]([^"'`]+)["'`]/g,
      /service\.(?:get|post|put|patch|delete|request|call)\(["'`]([^"'`]+)["'`]/g,
      /apiClient\.(?:get|post|put|patch|delete)\(["'`]([^"'`]+)["'`]/g,
      /\.request\(["'`]([^"'`]+)["'`]/g,
    ];
    for (const pattern of extractPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let ep = match[1].trim();
        if (ep.length < 3 || ep.startsWith('data:') || ep.startsWith('javascript:')) continue;
        if (!ep.startsWith('http')) {
          if (sourceUrl) {
            try {
              const base = new URL(sourceUrl);
              ep = ep.startsWith('/') ? `${base.origin}${ep}` : `${base.origin}/${ep}`;
            } catch { continue; }
          }
        }
        if (!found.has(ep)) {
          const type = ep.includes('/graphql') ? 'graphql' :
            ep.includes('/ws') || ep.includes('wss://') ? 'websocket' :
            ep.includes('/soap') ? 'soap' : 'rest';
          found.set(ep, { url: ep, type });
        }
      }
    }
    return Array.from(found.values());
  }

  /**
   * Detects authentication requirements from response headers
   * @param {Object} headers
   * @returns {string|null}
   */
  detectAuth(headers) {
    if (!headers) return null;
    const headerStr = JSON.stringify(headers).toLowerCase();
    for (const { regex, name } of this.authPatterns) {
      if (regex.test(headerStr)) return name;
    }
    if (headers['www-authenticate']) return `WWW-Authenticate: ${headers['www-authenticate']}`;
    if (headers['set-cookie']) return 'Session Cookie';
    return null;
  }

  /**
   * Enhances endpoints by probing them with HTTP methods
   * @param {Array<{url: string, type: string}>} endpoints
   * @returns {Promise<Array<ApiEndpoint>>}
   */
  async enhanceEndpoints(endpoints) {
    const enhanced = [];
    for (const ep of endpoints) {
      if (this.endpoints.has(ep.url)) {
        enhanced.push(this.endpoints.get(ep.url));
        continue;
      }
      try {
        const probeResults = [];
        const allowedMethods = [];
        for (const method of this.methodsProbed) {
          const result = await this.probeMethod(ep.url, method);
          probeResults.push({ method, status: result.status, elapsed: result.elapsed });
          if (result.status && result.status !== 405 && result.status !== 501 && result.status !== 404) {
            allowedMethods.push(method);
          }
          await new Promise((r) => setTimeout(r, 50));
        }
        const getResult = probeResults.find((p) => p.method === 'GET');
        const authType = getResult ? this.detectAuth(getResult.headers) : null;
        const entry = {
          url: ep.url,
          methods: allowedMethods.length > 0 ? allowedMethods : ['GET'],
          type: ep.type,
          statusCode: getResult ? getResult.status : 0,
          authType,
          probes: probeResults,
        };
        this.endpoints.set(ep.url, entry);
        enhanced.push(entry);
      } catch (err) {
        this.log(`Failed to probe ${ep.url}: ${err.message}`, 'warn');
        enhanced.push({ url: ep.url, methods: ['GET'], type: ep.type, statusCode: 0, authType: null });
      }
    }
    return enhanced;
  }

  /**
   * Extracts endpoints from a local HTML/JS file
   * @param {string} filePath
   * @returns {{file: string, endpoints: Array<ApiEndpoint>, raw: Array<{url: string, type: string}>}}
   */
  async extractFromFile(filePath) {
    this.log(`Reading file: ${filePath}`);
    const content = fs.readFileSync(filePath, 'utf-8');
    const raw = this.extractFromContent(content, filePath);
    this.log(`Found ${raw.length} raw endpoint references in ${path.basename(filePath)}`);
    const endpoints = await this.enhanceEndpoints(raw);
    return { file: filePath, endpoints, raw };
  }

  /**
   * Recursively crawls a URL to discover API endpoints
   * @param {string} startUrl
   * @param {number} [depth]
   * @returns {Promise<Array<ApiEndpoint>>}
   */
  async crawlUrl(startUrl, depth) {
    const maxDepth = depth !== undefined ? depth : this.depth;
    const queue = [{ url: startUrl, depth: 0 }];
    const allEndpoints = [];
    const jsFiles = [];

    while (queue.length > 0) {
      const { url, depth: currentDepth } = queue.shift();
      if (this.visited.has(url) || currentDepth > maxDepth) continue;
      this.visited.add(url);

      this.log(`Crawling (depth ${currentDepth}/${maxDepth}): ${url}`);
      try {
        const response = await this.fetchUrl(url);
        const contentType = response.contentType.toLowerCase();

        if (contentType.includes('text/html') || contentType.includes('application/xhtml')) {
          const raw = this.extractFromContent(response.body, url);
          this.log(`Found ${raw.length} endpoint references in ${url}`);
          const enhanced = await this.enhanceEndpoints(raw);
          allEndpoints.push(...enhanced);

          const linkMatches = response.body.match(/<a[^>]+href=["']([^"']+)["']/gi);
          if (linkMatches && currentDepth < maxDepth) {
            for (const link of linkMatches) {
              const hrefMatch = link.match(/href=["']([^"']+)["']/);
              if (!hrefMatch) continue;
              let href = hrefMatch[1];
              if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;
              try {
                const resolved = new URL(href, url).href;
                if (!this.visited.has(resolved) && resolved.startsWith(startUrl)) {
                  queue.push({ url: resolved, depth: currentDepth + 1 });
                }
              } catch { /* skip malformed URLs */ }
            }
          }

          const scriptMatches = response.body.match(/<script[^>]+src=["']([^"']+)["']/gi);
          if (scriptMatches) {
            for (const sm of scriptMatches) {
              const srcMatch = sm.match(/src=["']([^"']+)["']/);
              if (!srcMatch) continue;
              try {
                const jsUrl = new URL(srcMatch[1], url).href;
                if (jsUrl.endsWith('.js') && !this.visited.has(jsUrl)) {
                  jsFiles.push(jsUrl);
                  this.visited.add(jsUrl);
                }
              } catch { /* skip */ }
            }
          }
        } else if (contentType.includes('javascript') || url.endsWith('.js')) {
          const raw = this.extractFromContent(response.body, url);
          if (raw.length > 0) {
            this.log(`Found ${raw.length} endpoint references in JS: ${url}`);
            const enhanced = await this.enhanceEndpoints(raw);
            allEndpoints.push(...enhanced);
          }
        } else if (contentType.includes('json')) {
          const raw = this.extractFromContent(response.body, url);
          if (raw.length > 0) {
            const enhanced = await this.enhanceEndpoints(raw);
            allEndpoints.push(...enhanced);
          }
        }
      } catch (err) {
        this.log(`Error crawling ${url}: ${err.message}`, 'warn');
      }
    }

    for (const jsUrl of jsFiles) {
      try {
        const response = await this.fetchUrl(jsUrl);
        const raw = this.extractFromContent(response.body, jsUrl);
        if (raw.length > 0) {
          const enhanced = await this.enhanceEndpoints(raw);
          allEndpoints.push(...enhanced);
        }
      } catch { /* skip failed JS */ }
    }

    return allEndpoints;
  }

  /**
   * Detects API documentation endpoints
   * @param {string} baseUrl
   * @returns {Promise<Array<{path: string, type: string, status: number}>>}
   */
  async detectApiDocs(baseUrl) {
    const docPaths = [
      { path: '/api/docs', type: 'Swagger UI' },
      { path: '/api/v1/docs', type: 'Swagger UI' },
      { path: '/api/v2/docs', type: 'Swagger UI' },
      { path: '/api/swagger', type: 'Swagger UI' },
      { path: '/api/swagger.json', type: 'Swagger JSON' },
      { path: '/api/swagger.yaml', type: 'Swagger YAML' },
      { path: '/api/openapi.json', type: 'OpenAPI JSON' },
      { path: '/api/openapi.yaml', type: 'OpenAPI YAML' },
      { path: '/swagger', type: 'Swagger UI' },
      { path: '/swagger.json', type: 'Swagger JSON' },
      { path: '/swagger.yaml', type: 'Swagger YAML' },
      { path: '/openapi.json', type: 'OpenAPI JSON' },
      { path: '/docs', type: 'Docs' },
      { path: '/graphql', type: 'GraphQL' },
      { path: '/graphql?query={__typename}', type: 'GraphQL Introspect' },
      { path: '/api/graphql', type: 'GraphQL' },
      { path: '/v1/graphql', type: 'GraphQL' },
      { path: '/api/v1', type: 'API Root' },
      { path: '/api/v2', type: 'API Root' },
      { path: '/api/v3', type: 'API Root' },
      { path: '/api/health', type: 'Health' },
      { path: '/health', type: 'Health' },
      { path: '/api/status', type: 'Status' },
      { path: '/status', type: 'Status' },
      { path: '/api/version', type: 'Version' },
      { path: '/version', type: 'Version' },
    ];
    const results = [];
    for (const { path: docPath, type } of docPaths) {
      try {
        const fullUrl = `${baseUrl.replace(/\/+$/, '')}${docPath}`;
        const methodsToTry = ['GET', 'POST', 'OPTIONS'];
        for (const method of methodsToTry) {
          const result = await this.probeMethod(fullUrl, method);
          if (result.status && result.status !== 404) {
            results.push({ path: docPath, type, method, status: result.status });
            break;
          }
        }
      } catch { /* skip */ }
    }
    return results;
  }

  /**
   * Detects WebSocket endpoints from page content
   * @param {string} content
   * @param {string} baseUrl
   * @returns {string[]}
   */
  detectWebSockets(content, baseUrl) {
    const wsEndpoints = [];
    const wsPatterns = [
      /new\s+WebSocket\(["'`]([^"'`]+)["'`]/g,
      /ws:\/\//g,
      /wss:\/\//g,
      /SockJS\(["'`]([^"'`]+)["'`]/g,
      /io\(["'`]([^"'`]+)["'`]/g,
      /io\.connect\(["'`]([^"'`]+)["'`]/g,
      /socket\.io/g,
      /Pusher\(/g,
      /WebSocketClient\(/g,
      /connect\(["'`]([^"'`]+)["'`]/g,
    ];
    for (const pattern of wsPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let wsUrl = match[1] || match[0];
        try {
          const resolved = new URL(wsUrl, baseUrl).href;
          wsEndpoints.push(resolved);
        } catch { wsEndpoints.push(wsUrl); }
      }
    }
    return [...new Set(wsEndpoints)];
  }

  /**
   * Detects authentication endpoints (login, register, etc.)
   * @param {string} content
   * @param {string} baseUrl
   * @returns {string[]}
   */
  detectAuthEndpoints(content, baseUrl) {
    const authEndpoints = [];
    const authPatterns = [
      /\/login/g, /\/signin/g, /\/signup/g, /\/register/g,
      /\/auth\//g, /\/oauth\//g, /\/token\//g,
      /\/password\/reset/g, /\/password\/change/g,
      /\/forgot-password/g, /\/reset-password/g,
      /\/logout/g, /\/signout/g,
      /\/mfa\//g, /\/2fa\//g, /\/verify\//g,
      /\/sso\//g, /\/saml\//g, /\/openid\//g,
      /\/authorize/g, /\/authenticate/g, /\/session\//g,
    ];
    for (const pattern of authPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const full = match[0];
        let resolved;
        try {
          resolved = new URL(full, baseUrl).href;
        } catch {
          resolved = full.startsWith('/') ? `${new URL(baseUrl).origin}${full}` : full;
        }
        authEndpoints.push(resolved);
      }
    }
    return [...new Set(authEndpoints)];
  }

  /**
   * Identifies REST API patterns from HTTP responses
   * @param {Array<ApiEndpoint>} endpoints
   * @returns {{rest: ApiEndpoint[], graphql: ApiEndpoint[], soap: ApiEndpoint[], websocket: ApiEndpoint[]}}
   */
  categorizeEndpoints(endpoints) {
    const categorized = { rest: [], graphql: [], soap: [], websocket: [], rpc: [] };
    for (const ep of endpoints) {
      if (categorized[ep.type]) {
        categorized[ep.type].push(ep);
      } else {
        categorized.rest.push(ep);
      }
    }
    return categorized;
  }

  /**
   * Generates a summary report
   * @param {Array<ApiEndpoint>} endpoints
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(endpoints, metadata = {}) {
    const categorized = this.categorizeEndpoints(endpoints);
    const uniqueUrls = [...new Set(endpoints.map((e) => e.url))];
    const methodsUsed = new Set();
    endpoints.forEach((e) => e.methods.forEach((m) => methodsUsed.add(m)));
    const authTypes = new Set(endpoints.filter((e) => e.authType).map((e) => e.authType));
    const byStatus = {};
    endpoints.forEach((e) => {
      const key = e.statusCode ? `${e.statusCode}` : 'unknown';
      byStatus[key] = (byStatus[key] || 0) + 1;
    });
    return {
      metadata,
      summary: {
        totalUnique: uniqueUrls.length,
        totalWithProbes: endpoints.length,
        byType: {
          rest: categorized.rest.length,
          graphql: categorized.graphql.length,
          soap: categorized.soap.length,
          websocket: categorized.websocket.length,
          rpc: categorized.rpc.length,
        },
        methodsDiscovered: [...methodsUsed].sort(),
        authMethodsFound: [...authTypes],
        byStatusCode: byStatus,
      },
      endpoints: Array.from(this.endpoints.values()),
    };
  }

  /**
   * Runs full extraction pipeline
   * @param {ExtractApisOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const startTime = Date.now();
    let endpoints = [];
    let apiDocs = [];
    const metadata = { startTime: new Date().toISOString(), input: {} };

    if (options.file) {
      metadata.input.type = 'file';
      metadata.input.path = options.file;
      const result = await this.extractFromFile(options.file);
      endpoints = result.endpoints;
      if (options.url && result.raw.length > 0) {
        const baseUrl = options.url.replace(/\/+$/, '');
        apiDocs = await this.detectApiDocs(baseUrl);
      }
    } else if (options.url) {
      metadata.input.type = 'url';
      metadata.input.url = options.url;
      this.log(`Starting crawl of ${options.url} with depth ${this.depth}`);
      endpoints = await this.crawlUrl(options.url, this.depth);
      this.log(`Crawl completed. Found ${endpoints.length} raw endpoint references.`);
      apiDocs = await this.detectApiDocs(options.url);
      const pageContent = await this.fetchUrl(options.url);
      const wsEndpoints = this.detectWebSockets(pageContent.body, options.url);
      const authEps = this.detectAuthEndpoints(pageContent.body, options.url);
      if (wsEndpoints.length > 0) {
        for (const ws of wsEndpoints) {
          if (!this.endpoints.has(ws)) {
            this.endpoints.set(ws, { url: ws, methods: ['WS'], type: 'websocket', statusCode: null, authType: null });
          }
        }
      }
      if (authEps.length > 0) {
        for (const ae of authEps) {
          if (!this.endpoints.has(ae)) {
            this.endpoints.set(ae, { url: ae, methods: ['GET', 'POST'], type: 'rest', statusCode: null, authType: 'Authentication' });
          }
        }
      }
    } else {
      throw new Error('Either --url or --file must be provided');
    }

    if (endpoints.length === 0 && this.endpoints.size === 0) {
      this.log('No API endpoints found', 'warn');
    }

    const report = this.generateReport(endpoints, {
      ...metadata,
      elapsed: Date.now() - startTime,
      apiDocsFound: apiDocs || [],
    });

    if (options.output) {
      const outPath = path.resolve(options.output);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      this.log(`Report written to ${outPath}`);
    }

    return report;
  }
}

/**
 * Parses command line arguments
 * @returns {ExtractApisOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { depth: 2, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':
        options.url = args[++i];
        break;
      case '--file':
        options.file = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--depth':
        options.depth = parseInt(args[++i], 10);
        if (isNaN(options.depth) || options.depth < 1) {
          process.stderr.write('Error: --depth must be a positive integer\n');
          process.exit(1);
        }
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
        if (!options.url) options.url = args[i];
        break;
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
 * Prints help text to stderr
 */
function printHelp() {
  const help = `
API Endpoint Discovery Tool - extract-apis.js
Extracts API endpoints from web pages and JavaScript files.

USAGE:
  node extract-apis.js --url <target-url> [options]
  node extract-apis.js --file <local-file> [options]

OPTIONS:
  --url <url>        Target URL to crawl for API endpoints
  --file <path>      Local HTML/JS file to analyze
  --output <path>    Write results to JSON file
  --depth <number>   Crawl depth for URL mode (default: 2)
  --silent           Suppress verbose output (JSON to stdout only)
  --timeout <ms>     Request timeout in milliseconds (default: 15000)
  --help, -h         Show this help message

EXAMPLES:
  node extract-apis.js --url https://example.com
  node extract-apis.js --url https://example.com --depth 3 --output apis.json
  node extract-apis.js --file ./page.html --output endpoints.json
  node extract-apis.js --url https://example.com --silent > report.json
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const extractor = new ApiExtractor(options);
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

module.exports = { ApiExtractor };
