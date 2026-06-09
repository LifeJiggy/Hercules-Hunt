#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');
const readline = require('readline');

/**
 * @typedef {Object} FuzzResult
 * @property {string} url - Fuzzed URL
 * @property {string} method - HTTP method used
 * @property {number} status - Response status code
 * @property {number} size - Response body size in bytes
 * @property {number} time - Response time in milliseconds
 * @property {string} contentType - Response content type
 * @property {string} location - Redirect location (if 3xx)
 * @property {Object} headers - Response headers
 * @property {string} category - Status category (2xx, 3xx, 4xx, 5xx)
 * @property {boolean} interesting - Whether result is considered interesting
 * @property {string|null} error - Error message if request failed
 */

/**
 * @typedef {Object} AccessControlResult
 * @property {string} path - Tested path
 * @property {string} authState - Auth state label
 * @property {number} status - Response status code
 * @property {number} size - Response body size
 * @property {boolean} accessible - Whether accessible in this auth state
 * @property {Object} headers - Response headers
 */

/**
 * @typedef {Object} EndpointFuzzerOptions
 * @property {string} target - Target base URL
 * @property {string} [wordlist] - Path to wordlist file
 * @property {string[]} [methods] - HTTP methods to test
 * @property {string[]} [extensions] - File extensions to test
 * @property {string} [output] - Output file path
 * @property {number} [threads=10] - Concurrency level
 * @property {number} [delay=50] - Delay between requests in ms
 * @property {number} [filterSize] - Filter out responses with exact body size
 * @property {number} [filterCode] - Filter out responses with exact status code
 * @property {boolean} [silent=false] - Suppress verbose output
 */

class EndpointFuzzer {
  /**
   * @param {EndpointFuzzerOptions} options
   */
  constructor(options = {}) {
    this.target = options.target ? options.target.replace(/\/+$/, '') : '';
    this.wordlistPath = options.wordlist || '';
    this.methods = options.methods || ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE'];
    this.extensions = options.extensions || ['.php', '.asp', '.aspx', '.jsp', '.json', '.xml', '.config', '.bak', '.old', '.swp', '.save', '.tar.gz', '.zip', '.tgz', '.sql', '.db', '.log', '.txt', '.inc', '.class', '.jar', '.war', '.properties', '.yml', '.yaml', '.env', '.dist', '.local', '.dump', '.csv', '.xls', '.xlsx'];
    this.output = options.output || '';
    this.threads = options.threads || 10;
    this.delay = options.delay || 50;
    this.filterSize = options.filterSize || null;
    this.filterCode = options.filterCode || null;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 15000;
    this.userAgent = 'Hercules-Hunt-Endpoint-Fuzzer/1.0';
    this.results = [];
    this.wordlist = [];
    this.totalRequests = 0;
    this.startTime = Date.now();
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
   * Makes an HTTP request with timing
   * @param {string} targetUrl
   * @param {string} [method='GET']
   * @param {string|null} [body=null]
   * @returns {Promise<{status: number, headers: Object, body: string, elapsed: number}>}
   */
  async fetchUrl(targetUrl, method = 'GET', body = null) {
    const parsed = new URL(targetUrl);
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
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {}, body: '', elapsed: 0 }); });
      req.on('error', () => resolve({ status: 0, headers: {}, body: '', elapsed: 0 }));
      if (body) req.write(body);
      req.end();
    });
  }

  /**
   * Loads a wordlist from a file
   * @param {string} filePath
   * @returns {Promise<string[]>}
   */
  async loadWordlist(filePath) {
    const lines = [];
    if (!fs.existsSync(filePath)) {
      throw new Error(`Wordlist file not found: ${filePath}`);
    }
    const rl = readline.createInterface({
      input: fs.createReadStream(filePath),
      crlfDelay: Infinity,
    });
    for await (const line of rl) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) {
        lines.push(trimmed);
      }
    }
    this.log(`Loaded ${lines.length} entries from ${path.basename(filePath)}`);
    return lines;
  }

  /**
   * Loads default wordlist paths
   * @returns {string[]}
   */
  getDefaultWordlist() {
    return [
      'admin', 'api', 'v1', 'v2', 'v3', 'login', 'logout', 'signin', 'signup',
      'register', 'auth', 'oauth', 'callback', 'webhook', 'health', 'status',
      'metrics', 'info', 'version', 'ping', 'test', 'debug', 'trace', 'config',
      'configuration', 'backup', 'backup.zip', 'backup.tar.gz', 'db', 'database',
      'dump', 'sql', 'migrate', 'migration', 'seed', 'seeds', 'data', 'assets',
      'static', 'public', 'private', 'internal', 'external', 'upload', 'uploads',
      'download', 'downloads', 'file', 'files', 'image', 'images', 'img', 'css',
      'js', 'javascript', 'fonts', 'media', 'video', 'doc', 'docs', 'documents',
      'pdf', 'csv', 'export', 'import', 'report', 'reports', 'logs', 'log',
      'error', 'errors', 'exception', 'exceptions', 'stacktrace', 'trace',
      'session', 'sessions', 'user', 'users', 'account', 'accounts', 'profile',
      'profiles', 'settings', 'preferences', 'notification', 'notifications',
      'message', 'messages', 'chat', 'inbox', 'mail', 'email', 'emails',
      'search', 'filter', 'sort', 'paginate', 'page', 'pages', 'post', 'posts',
      'article', 'articles', 'blog', 'news', 'feed', 'rss', 'atom', 'sitemap',
      'robots.txt', 'crossdomain.xml', 'clientaccesspolicy.xml',
      '.well-known', '.git', '.svn', '.env', '.gitignore', '.htaccess',
      'index', 'default', 'home', 'main', 'landing', 'dashboard',
      'panel', 'console', 'management', 'adminpanel', 'cp', 'cpanel',
      'wp-admin', 'wp-content', 'wp-includes', 'administrator',
      'moderator', 'superuser', 'root', 'system', 'shell', 'cmd',
      'exec', 'eval', 'phpinfo', 'info.php', 'test.php',
      'swagger', 'swagger.json', 'swagger.yaml', 'openapi.json',
      'api-docs', 'api/documentation', 'graphql', 'graphiql',
      'index.html', 'index.php', 'index.asp', 'index.aspx', 'index.jsp',
      'default.aspx', 'default.asp', 'default.php',
      'web.config', 'app.config', 'application.config',
      'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
      'Makefile', 'package.json', 'composer.json', 'Gemfile',
      'requirements.txt', 'Pipfile', 'yarn.lock', 'package-lock.json',
      'Procfile', '.env.example', '.env.local', '.env.production',
      'credentials', 'credentials.json', 'key.json', 'secret.json',
      'id_rsa', 'id_dsa', '.ssh', 'authorized_keys',
      'npm-debug.log', 'yarn-error.log', 'error.log', 'access.log',
      '.DS_Store', 'Thumbs.db', 'desktop.ini',
    ];
  }

  /**
   * Classifies HTTP status code into category
   * @param {number} status
   * @returns {string}
   */
  classifyStatus(status) {
    if (status >= 200 && status < 300) return '2xx';
    if (status >= 300 && status < 400) return '3xx';
    if (status >= 400 && status < 500) return '4xx';
    if (status >= 500) return '5xx';
    return 'unknown';
  }

  /**
   * Determines if a response is interesting
   * @param {number} status
   * @param {number} size
   * @returns {boolean}
   */
  isInteresting(status, size) {
    if (status === 0) return false;
    if (status >= 200 && status < 300) return true;
    if (status >= 300 && status < 400) return true;
    if (status === 401 || status === 403) return true;
    if (status === 405) return true;
    if (status === 500 || status === 502 || status === 503) return true;
    return false;
  }

  /**
   * Fuzzes paths against the target
   * @param {string} baseUrl
   * @param {string[]} paths
   * @returns {Promise<FuzzResult[]>}
   */
  async fuzzPaths(baseUrl, paths) {
    const results = [];
    const chunks = [];
    for (let i = 0; i < paths.length; i += this.threads) {
      chunks.push(paths.slice(i, i + this.threads));
    }

    for (const chunk of chunks) {
      const batch = chunk.map(async (p) => {
        const fuzzUrl = `${baseUrl}/${p}`;
        try {
          const response = await this.fetchUrl(fuzzUrl, 'GET');
          const size = response.body.length;
          const category = this.classifyStatus(response.status);
          const interesting = this.isInteresting(response.status, size);

          if (this.filterSize && size === this.filterSize) return null;
          if (this.filterCode && response.status === this.filterCode) return null;

          const result = {
            url: fuzzUrl,
            method: 'GET',
            status: response.status,
            size,
            time: response.elapsed,
            contentType: response.headers['content-type'] || '',
            location: response.headers['location'] || '',
            headers: {
              'content-type': response.headers['content-type'],
              'content-length': response.headers['content-length'],
              'server': response.headers['server'],
              'location': response.headers['location'],
            },
            category,
            interesting,
            error: null,
          };

          if (interesting) {
            this.log(`${response.status} ${fuzzUrl} (${size} bytes, ${response.elapsed}ms)`);
          }

          this.totalRequests++;
          return result;
        } catch {
          this.totalRequests++;
          return null;
        }
      });

      const batchResults = await Promise.all(batch);
      for (const r of batchResults) {
        if (r) results.push(r);
      }

      if (this.delay > 0) {
        await new Promise((r) => setTimeout(r, this.delay));
      }
    }

    return results;
  }

  /**
   * Fuzzes different HTTP methods on a list of paths
   * @param {string} baseUrl
   * @param {string[]} paths
   * @param {string[]} methods
   * @returns {Promise<FuzzResult[]>}
   */
  async fuzzMethods(baseUrl, paths, methods) {
    const results = [];
    for (const p of paths) {
      const fuzzUrl = `${baseUrl}/${p}`;
      for (const method of methods) {
        if (method === 'GET' && !p.includes('?')) continue;
        try {
          const response = await this.fetchUrl(fuzzUrl, method, method === 'POST' || method === 'PUT' || method === 'PATCH' ? 'test=1' : null);
          const size = response.body.length;
          const interesting = response.status !== 404 && response.status !== 405 && response.status !== 501;

          if (this.filterCode && response.status === this.filterCode) continue;
          if (this.filterSize && size === this.filterSize) continue;

          const result = {
            url: fuzzUrl,
            method,
            status: response.status,
            size,
            time: response.elapsed,
            contentType: response.headers['content-type'] || '',
            location: response.headers['location'] || '',
            headers: {},
            category: this.classifyStatus(response.status),
            interesting,
            error: null,
          };

          if (interesting && response.status !== 200) {
            this.log(`[${method}] ${response.status} ${fuzzUrl} (${size} bytes, ${response.elapsed}ms)`);
          }

          results.push(result);
          this.totalRequests++;
        } catch {
          this.totalRequests++;
        }

        if (this.delay > 0) {
          await new Promise((r) => setTimeout(r, this.delay));
        }
      }
    }
    return results;
  }

  /**
   * Fuzzes file extensions on discovered paths
   * @param {string} baseUrl
   * @param {string[]} paths
   * @param {string[]} extensions
   * @returns {Promise<FuzzResult[]>}
   */
  async fuzzExtensions(baseUrl, paths, extensions) {
    const results = [];
    for (const p of paths) {
      const basePath = p.replace(/\.[^/.]+$/, '');
      for (const ext of extensions) {
        const fuzzUrl = `${baseUrl}/${basePath}${ext}`;
        try {
          const response = await this.fetchUrl(fuzzUrl, 'GET');
          const size = response.body.length;
          const interesting = this.isInteresting(response.status, size);

          if (this.filterCode && response.status === this.filterCode) continue;
          if (this.filterSize && size === this.filterSize) continue;

          const result = {
            url: fuzzUrl,
            method: 'GET',
            status: response.status,
            size,
            time: response.elapsed,
            contentType: response.headers['content-type'] || '',
            location: response.headers['location'] || '',
            headers: {},
            category: this.classifyStatus(response.status),
            interesting,
            error: null,
          };

          if (interesting) {
            this.log(`${response.status} ${fuzzUrl} (${size} bytes, ${response.elapsed}ms)`);
          }

          results.push(result);
          this.totalRequests++;
        } catch {
          this.totalRequests++;
        }

        if (this.delay > 0) {
          await new Promise((r) => setTimeout(r, this.delay));
        }
      }
    }
    return results;
  }

  /**
   * Tests access control by requesting same path with different auth states
   * @param {string} baseUrl
   * @param {string} path
   * @param {Array<{label: string, headers: Object}>} authStates
   * @returns {Promise<AccessControlResult[]>}
   */
  async testAccessControl(baseUrl, path, authStates) {
    const results = [];
    const fuzzUrl = `${baseUrl}/${path}`;

    for (const state of authStates) {
      try {
        const response = await this.fetchUrl(fuzzUrl, 'GET', null, state.headers);
        results.push({
          path,
          authState: state.label,
          status: response.status,
          size: response.body.length,
          accessible: response.status >= 200 && response.status < 400,
          headers: {
            'content-type': response.headers['content-type'],
            'content-length': response.headers['content-length'],
            'set-cookie': response.headers['set-cookie'] ? 'present' : 'none',
          },
        });
        this.totalRequests++;
      } catch {
        results.push({
          path,
          authState: state.label,
          status: 0,
          size: 0,
          accessible: false,
          headers: {},
        });
        this.totalRequests++;
      }

      if (this.delay > 0) {
        await new Promise((r) => setTimeout(r, this.delay));
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
    const interesting = this.results.filter((r) => r.interesting);
    const byCategory = {};
    for (const r of this.results) {
      byCategory[r.category] = (byCategory[r.category] || 0) + 1;
    }
    const byMethod = {};
    for (const r of this.results) {
      byMethod[r.method] = (byMethod[r.method] || 0) + 1;
    }
    const byStatus = {};
    for (const r of this.results) {
      const key = `${r.status}`;
      byStatus[key] = (byStatus[key] || 0) + 1;
    }

    const contentTypeSummary = {};
    for (const r of this.results) {
      const ct = r.contentType.split(';')[0] || 'unknown';
      contentTypeSummary[ct] = (contentTypeSummary[ct] || 0) + 1;
    }

    const avgTime = this.results.length > 0
      ? Math.round(this.results.reduce((s, r) => s + r.time, 0) / this.results.length)
      : 0;

    const elapsed = Date.now() - this.startTime;
    const rate = Math.round(this.totalRequests / (elapsed / 1000));

    return {
      metadata: {
        ...metadata,
        generatedAt: new Date().toISOString(),
        duration: elapsed,
        requestsPerSecond: rate,
      },
      summary: {
        totalRequests: this.totalRequests,
        totalResults: this.results.length,
        interestingResults: interesting.length,
        averageResponseTime: avgTime,
        byStatusCodeCategory: byCategory,
        byStatusCode: byStatus,
        byMethod: byMethod,
        byContentType: contentTypeSummary,
      },
      interesting: interesting.slice(0, 500),
      results: this.results.slice(0, 2000),
    };
  }

  /**
   * Runs full fuzzing pipeline
   * @param {EndpointFuzzerOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    this.startTime = Date.now();
    this.log(`Starting endpoint fuzzer against ${this.target}`);

    if (this.wordlistPath) {
      this.wordlist = await this.loadWordlist(this.wordlistPath);
    } else {
      this.wordlist = this.getDefaultWordlist();
      this.log(`Using default wordlist with ${this.wordlist.length} entries`);
    }

    if (options.output) {
      fs.mkdirSync(path.dirname(path.resolve(options.output)), { recursive: true });
    }

    this.log(`Phase 1: Path fuzzing with ${this.wordlist.length} paths (${this.threads} threads)`);
    const pathResults = await this.fuzzPaths(this.target, this.wordlist);
    this.results.push(...pathResults);
    this.log(`Path fuzzing complete: ${pathResults.length} results`);

    const discoveredPaths = pathResults
      .filter((r) => r.interesting && r.status !== 404 && r.status !== 0)
      .map((r) => {
        const u = new URL(r.url);
        return u.pathname.replace(/^\//, '');
      });

    if (discoveredPaths.length > 0) {
      this.log(`Phase 2: Extension fuzzing on ${discoveredPaths.length} discovered paths`);
      const extResults = await this.fuzzExtensions(this.target, discoveredPaths, this.extensions);
      this.results.push(...extResults);
      this.log(`Extension fuzzing complete: ${extResults.length} results`);
    }

    if (this.methods.length > 0 && discoveredPaths.length > 0) {
      this.log(`Phase 3: Method fuzzing with ${this.methods.length} methods on ${discoveredPaths.length} paths`);
      const methodResults = await this.fuzzMethods(this.target, discoveredPaths.slice(0, 20), this.methods);
      this.results.push(...methodResults);
      this.log(`Method fuzzing complete: ${methodResults.length} results`);
    }

    const report = this.generateReport({
      target: this.target,
      wordlistSize: this.wordlist.length,
      methodsTested: this.methods,
      extensionsTested: this.extensions,
      concurrency: this.threads,
      delayMs: this.delay,
    });

    if (options.output) {
      const outPath = path.resolve(options.output);
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      this.log(`Report written to ${outPath}`);
    }

    this.log(`Fuzzing complete: ${this.totalRequests} requests in ${((Date.now() - this.startTime) / 1000).toFixed(1)}s`);
    return report;
  }
}

/**
 * Parses command line arguments
 * @returns {EndpointFuzzerOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { threads: 10, delay: 50, silent: false };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--target':
        options.target = args[++i];
        break;
      case '--wordlist':
        options.wordlist = args[++i];
        break;
      case '--methods':
        options.methods = args[++i].split(',').map((m) => m.trim().toUpperCase());
        break;
      case '--extensions':
        options.extensions = args[++i].split(',').map((e) => e.trim().startsWith('.') ? e.trim() : `.${e.trim()}`);
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--threads':
        options.threads = parseInt(args[++i], 10);
        if (isNaN(options.threads) || options.threads < 1) {
          process.stderr.write('Error: --threads must be a positive integer\n');
          process.exit(1);
        }
        break;
      case '--delay':
        options.delay = parseInt(args[++i], 10);
        if (isNaN(options.delay) || options.delay < 0) {
          process.stderr.write('Error: --delay must be a non-negative integer\n');
          process.exit(1);
        }
        break;
      case '--filter-size':
        options.filterSize = parseInt(args[++i], 10);
        break;
      case '--filter-code':
        options.filterCode = parseInt(args[++i], 10);
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
  if (!options.target) {
    process.stderr.write('Error: --target is required\n');
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
Endpoint Fuzzing Tool - endpoint-fuzzer.js
Fuzzes paths, HTTP methods, and file extensions to discover hidden endpoints.

USAGE:
  node endpoint-fuzzer.js --target <url> [options]

OPTIONS:
  --target <url>           Target base URL (required)
  --wordlist <path>        Path to wordlist file (default: built-in list)
  --methods <list>         Comma-separated HTTP methods (default: GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD,TRACE)
  --extensions <list>      Comma-separated extensions (default: .php,.asp,.aspx,.json,.xml,.bak,.old,.swp,.save,.tar.gz,...)
  --output <path>          Write results to JSON file
  --threads <number>       Concurrent requests (default: 10)
  --delay <ms>             Delay between request batches (default: 50)
  --filter-size <bytes>    Exclude responses with exact body size
  --filter-code <code>     Exclude responses with exact status code
  --silent                 Suppress verbose output
  --timeout <ms>           Request timeout in milliseconds (default: 15000)
  --help, -h               Show this help message

EXAMPLES:
  node endpoint-fuzzer.js --target https://example.com
  node endpoint-fuzzer.js --target https://example.com --wordlist paths.txt --threads 20
  node endpoint-fuzzer.js --target https://example.com --extensions .php,.asp,.jsp --filter-code 404
  node endpoint-fuzzer.js --target https://example.com --output fuzz-results.json --silent
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const fuzzer = new EndpointFuzzer(options);
    const report = await fuzzer.run(options);
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

module.exports = { EndpointFuzzer };
