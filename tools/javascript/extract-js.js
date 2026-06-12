#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

const MAX_URL_LENGTH = 8192;
const MAX_FILE_SIZE = 10 * 1024 * 1024;

/**
 * @typedef {Object} InlineScript
 * @property {number} index - Script index on the page
 * @property {number} length - Script content length
 * @property {string[]} endpoints - API endpoints found in script
 * @property {Object[]} secrets - Secrets found in script
 */

/**
 * @typedef {Object} ExternalScript
 * @property {string} url - Script source URL
 * @property {number} size - Downloaded size in bytes
 * @property {number} statusCode - HTTP status
 * @property {string[]} endpoints - API endpoints found
 * @property {Object[]} secrets - Secrets found
 */

/**
 * @typedef {Object} ExtractJsOptions
 * @property {string} [url] - Target URL
 * @property {string} [file] - Local HTML file to parse
 * @property {boolean} [inline=true] - Extract inline scripts
 * @property {boolean} [external=true] - Fetch and analyze external scripts
 * @property {string} [output] - Output file path
 * @property {boolean} [secrets=true] - Enable secret scanning
 * @property {number} [depth=1] - Recursive JS analysis depth
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class JsExtractor {
  constructor(options = {}) {
    this.inline = options.inline !== undefined ? options.inline : true;
    this.external = options.external !== undefined ? options.external : true;
    this.scanSecrets = options.secrets !== undefined ? options.secrets : true;
    this.depth = options.depth || 1;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 15000;
    this.userAgent = 'Hercules-Hunt-JS-Extractor/1.0';
    this.results = { inline: [], external: [], secrets: [], endpoints: [] };
    this.visitedJs = new Set();
    this.endpointPatterns = [
      /\/api\/[\w\-./?=&%]+/gi, /\/v\d+\/[\w\-./?=&%]+/gi,
      /\/rest\/[\w\-./?=&%]+/gi, /\/graphql[\w\-./?=&%]*/gi,
      /\/oauth[\w\-./?=&%]*/gi, /\/callback[\w\-./?=&%]*/gi,
      /\/webhook[\w\-./?=&%]*/gi, /\/ws\/[\w\-./?=&%]*/gi,
      /\/sse\/[\w\-./?=&%]*/gi, /\/stream[\w\-./?=&%]*/gi,
    ];
    this.secretPatterns = [
      { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
      { name: 'AWS Secret Key', regex: /aws[_-]?secret[_-]?key["'\s:=]+([a-zA-Z0-9\/+]{40})/gi, severity: 'critical' },
      { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g, severity: 'high' },
      { name: 'Google OAuth', regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g, severity: 'high' },
      { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z\-_]{10,}/g, severity: 'critical' },
      { name: 'Slack Webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/g, severity: 'critical' },
      { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g, severity: 'high' },
      { name: 'Bearer Token', regex: /bearer\s+[a-zA-Z0-9\-_.]+/gi, severity: 'high' },
      { name: 'API Key Generic', regex: /api[_-]?key["'\s:=]+([a-zA-Z0-9\-_.]{16,64})/gi, severity: 'high' },
      { name: 'Password', regex: /password["'\s:=]+([^"'&\s,]{8,})/gi, severity: 'critical' },
      { name: 'Secret', regex: /secret["'\s:=]+([^"'&\s,]{10,})/gi, severity: 'critical' },
      { name: 'Auth Token', regex: /auth[_-]?token["'\s:=]+([^"'&\s,]{8,})/gi, severity: 'high' },
      { name: 'Private Key', regex: /-----BEGIN\s?(RSA|EC|DSA|OPENSSH)?\s?PRIVATE\s?KEY-----/g, severity: 'critical' },
      { name: 'Firebase URL', regex: /[a-zA-Z0-9\-_]+\.firebaseio\.com/g, severity: 'medium' },
      { name: 'Firebase Config', regex: /apiKey:\s*["'][A-Za-z0-9]{30,}["']/g, severity: 'high' },
      { name: 'S3 Bucket', regex: /[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com/g, severity: 'medium' },
      { name: 'S3 Bucket URL', regex: /s3:\/\/[a-zA-Z0-9\-_.]+/g, severity: 'medium' },
      { name: 'GraphQL Endpoint', regex: /https?:\/\/[^"'\s,]+?\/graphql/g, severity: 'medium' },
      { name: 'Webhook URL', regex: /https?:\/\/hooks\.slack\.com\/[a-zA-Z0-9\/]+/g, severity: 'high' },
      { name: 'MongoDB URI', regex: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9\-_.:@/?&]+/g, severity: 'critical' },
      { name: 'PostgreSQL URI', regex: /postgres(?:\+srv)?:\/\/[a-zA-Z0-9\-_.:@/?&]+/g, severity: 'critical' },
      { name: 'MySQL URI', regex: /mysql:\/\/[a-zA-Z0-9\-_.:@/?&]+/g, severity: 'critical' },
      { name: 'Redis URI', regex: /redis:\/\/[a-zA-Z0-9\-_.:@/?&]+/g, severity: 'high' },
      { name: 'Stripe Key', regex: /sk_live_[0-9A-Za-z]{24,}/g, severity: 'critical' },
      { name: 'Stripe Publishable', regex: /pk_live_[0-9A-Za-z]{24,}/g, severity: 'medium' },
      { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
      { name: 'GitLab Token', regex: /glpat-[A-Za-z0-9\-_]{20,}/g, severity: 'critical' },
      { name: 'NPM Token', regex: /npm_[A-Za-z0-9]{36,}/g, severity: 'critical' },
      { name: 'Heroku API Key', regex: /[hH][eE][rR][oO][kK][uU].*[aA][pP][iI].*[kK][eE][yY].{0,5}["'\s:=]+([a-zA-Z0-9\-_]{20,})/g, severity: 'critical' },
      { name: 'SendGrid Key', regex: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}/g, severity: 'critical' },
      { name: 'Twilio SID', regex: /AC[a-zA-Z0-9]{32}/g, severity: 'high' },
      { name: 'Twilio Token', regex: /SK[a-zA-Z0-9]{32}/g, severity: 'high' },
      { name: 'Azure Key', regex: /AccountKey=[a-zA-Z0-9\/+]{86}/g, severity: 'critical' },
      { name: 'Azure Connection', regex: /DefaultEndpointsProtocol=https;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9\/+]{86}/g, severity: 'critical' },
      { name: 'Google Cloud Key', regex: /"type":\s*"service_account"/g, severity: 'critical' },
      { name: 'Docker Auth', regex: /"auths":\s*\{/g, severity: 'high' },
      { name: '.env Reference', regex: /process\.env\.[A-Za-z0-9_]+/g, severity: 'low' },
      { name: 'Sauce Labs', regex: /saucelabs\.com.*accessKey/g, severity: 'high' },
      { name: 'Facebook Token', regex: /EAACEdEose0cBA[0-9A-Za-z]+/g, severity: 'high' },
      { name: 'Google Captcha', regex: /6L[0-9A-Za-z\-_]{38}/g, severity: 'low' },
      { name: 'HashiCorp Token', regex: /hvs\.[A-Za-z0-9\-_]{36,}/g, severity: 'critical' },
      { name: 'Datadog Key', regex: /datadog.*api_key.{0,5}["'\s:=]+([a-zA-Z0-9]{32})/g, severity: 'high' },
    ];
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
   * Fetches a URL and returns the response
   * @param {string} targetUrl
   * @returns {Promise<{status: number, headers: Object, body: string}>}
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
          'Accept': '*/*',
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
          });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${targetUrl}`)); });
      req.on('error', (e) => reject(new Error(`Fetch error: ${e.message}`)));
      req.end();
    });
  }

  /**
   * Extracts API endpoints from JavaScript content
   * @param {string} content
   * @param {string} [sourceUrl='']
   * @returns {string[]}
   */
  extractEndpoints(content, sourceUrl = '') {
    const endpoints = new Set();
    for (const pattern of this.endpointPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let ep = match[0].trim();
        if (ep.length < 4) continue;
        if (sourceUrl && ep.startsWith('/')) {
          try {
            ep = new URL(ep, sourceUrl).href;
          } catch { /* keep relative */ }
        }
        endpoints.add(ep);
      }
    }
    const fetchPatterns = [
      /fetch\(["'`]([^"'`]+)["'`]/g,
      /axios\.(?:get|post|put|patch|delete|request|head|options)\(["'`]([^"'`]+)["'`]/g,
      /\$\.(?:get|post|ajax|put|delete|patch)\(["'`]([^"'`]+)["'`]/g,
      /XMLHttpRequest\.open\(["'`][A-Z]+["'`],\s*["'`]([^"'`]+)["'`]/g,
      /url:\s*["'`]([^"'`]+)["'`]/g,
      /endpoint:\s*["'`]([^"'`]+)["'`]/g,
      /api\.(?:get|post|put|patch|delete|call)\(["'`]([^"'`]+)["'`]/g,
      /client\.(?:get|post|put|patch|delete)\(["'`]([^"'`]+)["'`]/g,
      /service\.(?:get|post|put|patch|delete|request)\(["'`]([^"'`]+)["'`]/g,
      /\.post\(["'`]([^"'`]+)["'`]/g,
      /\.put\(["'`]([^"'`]+)["'`]/g,
      /\.delete\(["'`]([^"'`]+)["'`]/g,
      /\.patch\(["'`]([^"'`]+)["'`]/g,
      /\.get\(["'`]([^"'`]+)["'`]/g,
      /["'`]([^"'`]*\/api\/[a-zA-Z0-9_\-./?=&%]+)["'`]/g,
      /["'`]([^"'`]*\/graphql[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/v\d+(?:\/\d+)?[a-zA-Z0-9_\-./?=&%]*)["'`]/g,
      /["'`]([^"'`]*\/rest\/[a-zA-Z0-9_\-./?=&%]*)["'`]/g,
      /["'`]([^"'`]*\/oauth[a-zA-Z0-9_\-./?=&%]*)["'`]/g,
    ];
    for (const pattern of fetchPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let ep = match[1].trim().replace(/["'`]+$/, '').replace(/^["'`]+/, '');
        if (ep.length < 4 || ep.startsWith('data:') || ep.startsWith('javascript:')) continue;
        if (sourceUrl && ep.startsWith('/')) {
          try {
            ep = new URL(ep, sourceUrl).href;
          } catch { /* keep relative */ }
        }
        endpoints.add(ep);
      }
    }
    return [...endpoints].sort();
  }

  /**
   * Extracts secrets from JavaScript content
   * @param {string} content
   * @returns {Array<{type: string, value: string, severity: string, context: string}>}
   */
  extractSecrets(content) {
    const secrets = [];
    const lines = content.split('\n');
    for (const { name, regex, severity } of this.secretPatterns) {
      let match;
      while ((match = regex.exec(content)) !== null) {
        const value = match[0].slice(0, 120);
        const lineIdx = content.slice(0, match.index).split('\n').length;
        const contextLine = lines[lineIdx - 1] || '';
        const context = contextLine.slice(0, 150).trim();
        secrets.push({
          type: name,
          value,
          severity,
          position: match.index,
          line: lineIdx,
          context,
        });
      }
    }
    return secrets;
  }

  /**
   * Extracts inline scripts from HTML content
   * @param {string} html
   * @returns {Array<{index: number, content: string, type: string}>}
   */
  extractInlineScripts(html) {
    const scripts = [];
    const regex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
    let match;
    let idx = 0;
    while ((match = regex.exec(html)) !== null) {
      const attrs = match[1] || '';
      const content = match[2] || '';
      if (!/src=["']/i.test(attrs) && content.trim().length > 0) {
        const typeMatch = attrs.match(/type=["']([^"']+)["']/);
        const langMatch = attrs.match(/language=["']([^"']+)["']/);
        scripts.push({
          index: idx++,
          content,
          type: typeMatch ? typeMatch[1] : 'text/javascript',
          language: langMatch ? langMatch[1] : null,
          attrs: attrs.trim(),
        });
      }
    }
    return scripts;
  }

  /**
   * Extracts external script URLs from HTML content
   * @param {string} html
   * @param {string} baseUrl
   * @returns {Array<{src: string, resolved: string, attrs: string, async: boolean, defer: boolean}>}
   */
  extractExternalScripts(html, baseUrl) {
    const scripts = [];
    const regex = /<script\b([^>]*)src=["']([^"']+)["']([^>]*)>/gi;
    let match;
    while ((match = regex.exec(html)) !== null) {
      const preAttrs = match[1] || '';
      const src = match[2];
      const postAttrs = match[3] || '';
      try {
        const resolved = new URL(src, baseUrl).href;
        scripts.push({
          src,
          resolved,
          attrs: (preAttrs + ' ' + postAttrs).trim(),
          async: /async/i.test(preAttrs + postAttrs),
          defer: /defer/i.test(preAttrs + postAttrs),
          module: /type=["']module["']/i.test(preAttrs + postAttrs),
        });
      } catch { /* skip unresolvable URLs */ }
    }
    return scripts;
  }

  /**
   * Analyzes a single external JS file
   * @param {string} jsUrl
   * @param {number} [currentDepth=0]
   * @returns {Promise<Object>}
   */
  async analyzeExternalJs(jsUrl, currentDepth = 0) {
    if (this.visitedJs.has(jsUrl)) return null;
    this.visitedJs.add(jsUrl);
    try {
      this.log(`Fetching JS: ${jsUrl}`);
      const response = await this.fetchUrl(jsUrl);
      const endpoints = this.extractEndpoints(response.body, jsUrl);
      const secrets = this.scanSecrets ? this.extractSecrets(response.body) : [];
      const importMatches = response.body.match(/import\(["'`]([^"'`]+)["'`]\)/g) || [];
      const dynamicImports = [];
      for (const im of importMatches) {
        const impMatch = im.match(/import\(["'`]([^"'`]+)["'`]\)/);
        if (impMatch) {
          try {
            dynamicImports.push(new URL(impMatch[1], jsUrl).href);
          } catch { dynamicImports.push(impMatch[1]); }
        }
      }
      const result = {
        url: jsUrl,
        size: response.body.length,
        status: response.status,
        endpoints,
        endpointCount: endpoints.length,
        secrets,
        secretCount: secrets.length,
        dynamicImports,
        hasSourceMap: /\/\/#\s*sourceMappingURL=/i.test(response.body),
      };
      this.results.external.push(result);
      this.results.endpoints.push(...endpoints);
      this.results.secrets.push(...secrets);
      if (currentDepth < this.depth) {
        const nestedJsUrls = this.extractJsUrlsFromContent(response.body, jsUrl);
        for (const nestedUrl of nestedJsUrls) {
          if (!this.visitedJs.has(nestedUrl)) {
            await this.analyzeExternalJs(nestedUrl, currentDepth + 1);
          }
        }
      }
      return result;
    } catch (err) {
      this.log(`Failed to fetch ${jsUrl}: ${err.message}`, 'warn');
      return null;
    }
  }

  /**
   * Extracts JS URLs from a JavaScript content (for recursive analysis)
   * @param {string} content
   * @param {string} baseUrl
   * @returns {string[]}
   */
  extractJsUrlsFromContent(content, baseUrl) {
    const urls = [];
    const patterns = [
      /["'`]([^"'`]+\.js(?:\?[^"'`]*)?)["'`]/g,
      /require\(["'`]([^"'`]+\.js)["'`]\)/g,
      /import\s+["'`]([^"'`]+\.js)["'`]/g,
      /import\s+['"]([^'"]+\.js)['"]/g,
    ];
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let url = match[1];
        if (url.startsWith('http')) {
          urls.push(url);
        } else if (baseUrl) {
          try {
            urls.push(new URL(url, baseUrl).href);
          } catch { /* skip */ }
        }
      }
    }
    return [...new Set(urls)];
  }

  /**
   * Extracts source map URL from JS content
   * @param {string} content
   * @returns {string|null}
   */
  extractSourceMapUrl(content) {
    const match = content.match(/\/\/#\s*sourceMappingURL=(.+)/);
    if (match) {
      return match[1].trim();
    }
    match = content.match(/\/\*\s*#\s*sourceMappingURL=(.+?)\s*\*\//);
    return match ? match[1].trim() : null;
  }

  /**
   * Fetches and parses a source map if present
   * @param {string} jsUrl
   * @param {string} content
   * @returns {Promise<Object|null>}
   */
  async fetchSourceMap(jsUrl, content) {
    const smUrl = this.extractSourceMapUrl(content);
    if (!smUrl) return null;
    try {
      const fullUrl = new URL(smUrl, jsUrl).href;
      const response = await this.fetchUrl(fullUrl);
      const sm = JSON.parse(response.body);
      return {
        url: fullUrl,
        version: sm.version,
        sources: sm.sources || [],
        sourcesContent: sm.sourcesContent ? true : false,
        mappings: sm.mappings ? sm.mappings.length : 0,
        names: (sm.names || []).length,
      };
    } catch { return null; }
  }

  /**
   * Processes HTML content to extract all JS information
   * @param {string} html
   * @param {string} pageUrl
   * @returns {Promise<Object>}
   */
  async processHtml(html, pageUrl) {
    const result = { url: pageUrl, inlineScripts: [], externalScripts: [], totalEndpoints: 0, totalSecrets: 0 };

    if (this.inline) {
      const inlineScripts = this.extractInlineScripts(html);
      for (const script of inlineScripts) {
        const endpoints = this.extractEndpoints(script.content, pageUrl);
        const secrets = this.scanSecrets ? this.extractSecrets(script.content) : [];
        const entry = {
          index: script.index,
          length: script.content.length,
          type: script.type,
          endpoints,
          endpointCount: endpoints.length,
          secrets,
          secretCount: secrets.length,
        };
        result.inlineScripts.push(entry);
        this.results.inline.push(entry);
        this.results.endpoints.push(...endpoints);
        this.results.secrets.push(...secrets);
        result.totalEndpoints += endpoints.length;
        result.totalSecrets += secrets.length;
      }
      this.log(`Found ${inlineScripts.length} inline scripts with ${result.totalEndpoints} endpoints`);
    }

    if (this.external) {
      const externalScripts = this.extractExternalScripts(html, pageUrl);
      this.log(`Found ${externalScripts.length} external script references`);
      for (const script of externalScripts) {
        const entry = await this.analyzeExternalJs(script.resolved, 0);
        if (entry) {
          result.externalScripts.push(entry);
          result.totalEndpoints += entry.endpointCount || 0;
          result.totalSecrets += entry.secretCount || 0;
        }
      }
    }

    const allEndpoints = this.results.endpoints;
    const allSecrets = this.results.secrets;
    const uniqueEndpoints = [...new Set(allEndpoints)].sort();
    const secretsBySeverity = {};
    for (const s of allSecrets) {
      if (!secretsBySeverity[s.severity]) secretsBySeverity[s.severity] = [];
      secretsBySeverity[s.severity].push(s);
    }
    return {
      ...result,
      uniqueEndpoints,
      uniqueEndpointCount: uniqueEndpoints.length,
      secretsBySeverity,
      totalSecretsFound: allSecrets.length,
    };
  }

  /**
   * Runs extraction from a local file
   * @param {string} filePath
   * @returns {Promise<Object>}
   */
  async extractFromFile(filePath) {
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
    const fileName = path.basename(filePath);
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.html' || ext === '.htm' || ext === '.xhtml') {
      return await this.processHtml(content, `file://${path.resolve(filePath)}`);
    } else if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
      const endpoints = this.extractEndpoints(content, filePath);
      const secrets = this.scanSecrets ? this.extractSecrets(content) : [];
      return { file: filePath, type: 'js-file', endpoints, secrets, endpointCount: endpoints.length, secretCount: secrets.length };
    } else {
      const endpoints = this.extractEndpoints(content, filePath);
      const secrets = this.scanSecrets ? this.extractSecrets(content) : [];
      return { file: filePath, type: 'unknown', endpoints, secrets, endpointCount: endpoints.length, secretCount: secrets.length };
    }
  }

  /**
   * Extracts inline JS from HTML string without URL fetch
   * @param {string} html
   * @returns {Object}
   */
  extractInlineJsOnly(html) {
    const inlineScripts = this.extractInlineScripts(html);
    return inlineScripts.map((s) => ({
      index: s.index,
      length: s.length,
      content: s.content,
      endpoints: this.extractEndpoints(s.content),
      secrets: this.scanSecrets ? this.extractSecrets(s.content) : [],
    }));
  }

  /**
   * Detects JS framework and library usage
   * @param {string} content
   * @returns {Object}
   */
  detectFrameworks(content) {
    const frameworks = {};
    const patterns = [
      { name: 'React', regex: /React(\.|\[)/g },
      { name: 'ReactDOM', regex: /ReactDOM(\.|\[)/g },
      { name: 'Vue', regex: /new Vue|createApp|Vue\./g },
      { name: 'Angular', regex: /angular\.module|ng-app|NgModule/g },
      { name: 'jQuery', regex: /\$\.|jQuery\./g },
      { name: 'Axios', regex: /axios\./g },
      { name: 'Express', regex: /express\(\)|require\(['"]express['"]\)/g },
      { name: 'Next.js', regex: /next\//g },
      { name: 'Nuxt', regex: /nuxt\//g },
      { name: 'Svelte', regex: /svelte/g },
      { name: 'Alpine', regex: /alpinejs|x-data/g },
      { name: 'Tailwind', regex: /tailwindcss/g },
      { name: 'Bootstrap', regex: /bootstrap\./g },
      { name: 'Lodash', regex: /lodash|_\.(get|set|merge|assign)/g },
      { name: 'Moment', regex: /moment\(\)|moment\./g },
      { name: 'D3', regex: /d3\./g },
      { name: 'Three.js', regex: /THREE\./g },
      { name: 'Chart.js', regex: /Chart\./g },
      { name: 'Socket.IO', regex: /io\(|socket\.io/g },
      { name: 'Webpack', regex: /webpackChunk|__webpack_require__/g },
      { name: 'Babel', regex: /@babel\/|babel-polyfill/g },
      { name: 'TypeScript', regex: /\.ts\b|typescript/g },
      { name: 'Redux', regex: /createStore|redux/g },
      { name: 'MobX', regex: /mobx/g },
      { name: 'GraphQL', regex: /ApolloClient|gql`|graphql-tag/g },
    ];
    for (const { name, regex } of patterns) {
      const matches = content.match(regex);
      if (matches) {
        frameworks[name] = matches.length;
      }
    }
    return frameworks;
  }

  /**
   * Generates the final report
   * @param {Object} data
   * @returns {Object}
   */
  generateReport(data) {
    const allEndpoints = [...new Set(data.uniqueEndpoints || this.results.endpoints || [])].sort();
    const allSecrets = this.results.secrets || [];
    const criticalSecrets = allSecrets.filter((s) => s.severity === 'critical');
    const highSecrets = allSecrets.filter((s) => s.severity === 'high');
    return {
      metadata: {
        tool: 'extract-js.js',
        timestamp: new Date().toISOString(),
        input: data.url || data.file || 'unknown',
        inlineAnalyzed: this.inline,
        externalAnalyzed: this.external,
        secretScanning: this.scanSecrets,
      },
      summary: {
        totalInlineScripts: data.inlineScripts ? data.inlineScripts.length : 0,
        totalExternalScripts: data.externalScripts ? data.externalScripts.length : 0,
        uniqueEndpoints: allEndpoints.length,
        totalSecrets: allSecrets.length,
        criticalSecrets: criticalSecrets.length,
        highSecrets: highSecrets.length,
      },
      uniqueEndpoints: allEndpoints,
      secrets: {
        critical: criticalSecrets,
        high: highSecrets,
        other: allSecrets.filter((s) => s.severity !== 'critical' && s.severity !== 'high'),
      },
      inlineScripts: data.inlineScripts || [],
      externalScripts: data.externalScripts || [],
    };
  }

  /**
   * Runs the full extraction pipeline
   * @param {ExtractJsOptions} options
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
    let result;
    if (options.file) {
      result = await this.extractFromFile(options.file);
    } else if (options.url) {
      this.log(`Fetching page: ${options.url}`);
      const response = await this.fetchUrl(options.url);
      this.log(`Page loaded (${response.body.length} bytes, status ${response.status})`);
      result = await this.processHtml(response.body, options.url);
      const frameworks = this.detectFrameworks(response.body);
      result.frameworks = frameworks;
      if (response.body.includes('sourceMappingURL')) {
        const sm = await this.fetchSourceMap(options.url, response.body);
        if (sm) result.sourceMap = sm;
      }
    } else {
      if (options.inline) {
        result = { inlineScripts: [], externalScripts: [], uniqueEndpoints: [], frameworks: {} };
      } else {
        throw new Error('Either --url or --file is required for extraction');
      }
    }
    const report = this.generateReport(result);
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
 * @returns {ExtractJsOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { inline: true, external: true, secrets: true, depth: 1, silent: false };
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
        break;
      case '--inline':
        options.inline = args[++i] !== 'false';
        break;
      case '--external':
        options.external = args[++i] !== 'false';
        break;
      case '--secrets':
        options.secrets = args[++i] !== 'false';
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
JavaScript Extraction Tool - extract-js.js
Extracts inline and external JavaScript, discovers endpoints and secrets.

USAGE:
  node extract-js.js --url <target-url> [options]
  node extract-js.js --file <html-file> [options]

OPTIONS:
  --url <url>          Target URL to analyze
  --file <path>        Local HTML/JS file to parse
  --output <path>      Write results to JSON file
  --depth <number>     Recursive JS analysis depth (default: 1)
  --inline <bool>      Extract inline scripts (default: true)
  --external <bool>    Fetch external JS files (default: true)
  --secrets <bool>     Scan for secrets in JS (default: true)
  --silent             Suppress verbose output
  --help, -h           Show this help message

EXAMPLES:
  node extract-js.js --url https://example.com
  node extract-js.js --url https://example.com --depth 2 --output js-report.json
  node extract-js.js --file ./page.html --inline false
  node extract-js.js --url https://example.com --silent > data.json
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const extractor = new JsExtractor(options);
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

module.exports = { JsExtractor };
