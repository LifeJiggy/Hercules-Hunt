const http = require('http');
const https = require('https');
const { URL } = require('url');
const crypto = require('crypto');

class APIFuzzer {
  constructor(options = {}) {
    this.timeout = options.timeout || 10000;
    this.delay = options.delay || 200;
    this.maxRetries = options.maxRetries || 2;
    this.userAgent = options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
    this.proxy = options.proxy || null;
    this.results = [];
    this.interactions = [];
  }

  async send(method, url, options = {}) {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const body = options.body || null;
    const headers = {
      'User-Agent': this.userAgent,
      'Accept': '*/*',
      'Accept-Language': 'en-US,en;q=0.9',
      ...options.headers
    };
    if (body && !headers['Content-Type']) {
      headers['Content-Type'] = typeof body === 'string' ? 'application/x-www-form-urlencoded' : 'application/json';
    }

    return new Promise((resolve, reject) => {
      const reqOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: method.toUpperCase(),
        headers,
        timeout: this.timeout,
        rejectUnauthorized: false,
        ...(this.proxy ? { host: this.proxy.host, port: this.proxy.port, path: url } : {})
      };

      const startTime = Date.now();
      const req = lib.request(reqOptions, (res) => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const elapsed = Date.now() - startTime;
          const responseBody = Buffer.concat(chunks).toString();
          const result = {
            method: method.toUpperCase(),
            url,
            status: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            body: responseBody,
            bodyLength: responseBody.length,
            elapsed,
            timestamp: new Date().toISOString()
          };
          this.results.push(result);
          resolve(result);
        });
      });

      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.on('error', reject);

      if (body) {
        const data = typeof body === 'object' ? JSON.stringify(body) : body;
        req.write(data);
      }
      req.end();
    });
  }

  async fuzzMethod(endpoint) {
    const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT'];
    const results = [];
    for (const method of methods) {
      try {
        const res = await this.send(method, endpoint);
        results.push({ method, status: res.status, bodyLength: res.bodyLength, allowed: res.status !== 405 && res.status !== 501 });
        await this.sleep(this.delay);
      } catch { results.push({ method, status: 0, error: true }); }
    }
    this.interactions.push({ type: 'method_fuzz', endpoint, results });
    return results;
  }

  async fuzzHeaders(endpoint, extraHeaders = []) {
    const baseHeaders = {
      'X-Forwarded-For': '127.0.0.1',
      'X-Forwarded-Host': 'localhost',
      'X-Real-IP': '127.0.0.1',
      'X-Originating-IP': '127.0.0.1',
      'Client-IP': '127.0.0.1',
      'X-Remote-IP': '127.0.0.1',
      'X-Remote-Addr': '127.0.0.1',
      'X-ProxyUser-IP': '127.0.0.1',
      'X-Forwarded-Proto': 'https',
      'X-Original-URL': '/admin',
      'X-Rewrite-URL': '/admin',
      'X-HTTP-Method-Override': 'PUT',
      'Content-Type': 'application/json',
      'Accept': 'text/plain',
      'X-Debug': 'true',
      'X-Show-Errors': 'true'
    };
    if (extraHeaders.length) {
      extraHeaders.forEach(h => { baseHeaders[h.name] = h.value; });
    }
    const results = [];
    for (const [header, value] of Object.entries(baseHeaders)) {
      try {
        const res = await this.send('GET', endpoint, { headers: { [header]: value } });
        results.push({ header, value, status: res.status, bodyLength: res.bodyLength, interesting: res.status < 400 });
        await this.sleep(this.delay);
      } catch { results.push({ header, value, error: true }); }
    }
    this.interactions.push({ type: 'header_fuzz', endpoint, results });
    return results;
  }

  async fuzzParameters(endpoint, paramName, payloads) {
    const baseUrl = new URL(endpoint);
    const results = [];
    for (const payload of payloads) {
      baseUrl.searchParams.set(paramName, payload);
      try {
        const res = await this.send('GET', baseUrl.toString());
        const interesting = res.status < 400 || res.body.includes('error') === false;
        results.push({ param: paramName, payload, status: res.status, bodyLength: res.bodyLength, interesting });
        await this.sleep(this.delay);
      } catch { results.push({ param: paramName, payload, error: true }); }
    }
    this.interactions.push({ type: 'param_fuzz', endpoint, param: paramName, results });
    return results;
  }

  async fuzzJSON(endpoint, baseObject, mutations) {
    const results = [];
    for (const mutation of mutations) {
      const body = { ...baseObject, ...mutation };
      try {
        const res = await this.send('POST', endpoint, {
          body,
          headers: { 'Content-Type': 'application/json' }
        });
        results.push({ mutation: JSON.stringify(mutation), status: res.status, body: res.body.slice(0, 300) });
        await this.sleep(this.delay);
      } catch { results.push({ mutation: JSON.stringify(mutation), error: true }); }
    }
    return results;
  }

  async fuzzRateLimit(endpoint, requests = 100, concurrency = 10) {
    const start = Date.now();
    const results = [];
    const batches = [];
    for (let i = 0; i < requests; i += concurrency) {
      const batch = [];
      for (let j = 0; j < concurrency && (i + j) < requests; j++) {
        batch.push(this.send('GET', endpoint).catch(e => ({ status: 0, error: e.message })));
      }
      batches.push(Promise.all(batch));
      await this.sleep(50);
    }
    const allResults = (await Promise.all(batches)).flat();
    const elapsed = Date.now() - start;
    const statusCounts = {};
    allResults.forEach(r => { statusCounts[r.status] = (statusCounts[r.status] || 0) + 1; });
    const rateLimited = allResults.filter(r => r.status === 429 || r.status === 503).length;
    return {
      totalRequests: requests,
      elapsed,
      rateLimited,
      rateLimitDetected: rateLimited > requests * 0.1,
      statusCounts,
      results: allResults.slice(0, 20)
    };
  }

  async fuzzContentTypes(endpoint) {
    const contentTypes = [
      'application/json',
      'application/x-www-form-urlencoded',
      'text/plain',
      'application/xml',
      'text/xml',
      'multipart/form-data',
      'application/graphql',
      'application/javascript',
      'text/html'
    ];
    const results = [];
    for (const ct of contentTypes) {
      try {
        const res = await this.send('POST', endpoint, {
          body: 'test',
          headers: { 'Content-Type': ct }
        });
        results.push({ contentType: ct, status: res.status, body: res.body.slice(0, 200) });
        await this.sleep(this.delay);
      } catch { results.push({ contentType: ct, error: true }); }
    }
    return results;
  }

  compareResponses(baseline, responses) {
    return responses.map(r => {
      const diffs = {};
      if (r.status !== baseline.status) diffs.status = { baseline: baseline.status, current: r.status };
      if (r.bodyLength !== baseline.bodyLength) diffs.bodyLength = { baseline: baseline.bodyLength, current: r.bodyLength };
      if (r.elapsed > baseline.elapsed * 2) diffs.timing = { baseline: baseline.elapsed, current: r.elapsed };
      return { ...r, diffs, anomalous: Object.keys(diffs).length > 0 };
    }).filter(r => r.anomalous);
  }

  async scan(endpoint) {
    console.log(`[APIFuzzer] Scanning: ${endpoint}`);
    const baseline = await this.send('GET', endpoint);
    const methodResults = await this.fuzzMethod(endpoint);
    const headerResults = await this.fuzzHeaders(endpoint);
    const contentTypeResults = await this.fuzzContentTypes(endpoint);
    return {
      endpoint,
      baseline: { status: baseline.status, bodyLength: baseline.bodyLength, headers: baseline.headers },
      methods: methodResults,
      headers: headerResults,
      contentTypes: contentTypeResults,
      summary: {
        alternateMethods: methodResults.filter(r => r.allowed).map(r => r.method),
        interestingHeaders: headerResults.filter(r => r.interesting).map(r => r.header),
        totalRequests: this.results.length
      }
    };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async fuzzGraphQL(endpoint) {
    const queries = [
      '{__schema{types{name}}}', '{__typename}', 'query{__schema{queryType{name}}}',
      'mutation{__typename}', 'subscription{__typename}',
      '{__schema{directives{name}}}', '{__schema{types{fields{name}}}}'
    ];
    const results = [];
    for (const q of queries) {
      try {
        const res = await this.send('POST', endpoint, {
          body: JSON.stringify({ query: q }),
          headers: { 'Content-Type': 'application/json' }
        });
        results.push({ query: q.slice(0, 40), status: res.status, introspection: res.body.includes('__schema') || res.body.includes('types') });
        await this.sleep(this.delay);
      } catch { results.push({ query: q.slice(0, 40), error: true }); }
    }
    const introspected = results.filter(r => r.introspection);
    if (introspected.length) this.results.push({ type: 'graphql-introspection', count: introspected.length, severity: 'HIGH' });
    return results;
  }

  async detectWebSocket(endpoint) {
    try {
      if (typeof WebSocket === 'undefined') return { supported: false, reason: 'WebSocket not available' };
      const wsUrl = endpoint.replace(/^http/, 'ws') + '/websocket';
      const ws = new WebSocket(wsUrl);
      return await new Promise((resolve) => {
        ws.onopen = () => { ws.close(); resolve({ supported: true, url: wsUrl }); };
        ws.onerror = () => resolve({ supported: false });
        setTimeout(() => resolve({ supported: false, timeout: true }), 3000);
      });
    } catch { return { supported: false }; }
  }

  async fuzzAPIVersions(baseEndpoint) {
    const versions = ['v1', 'v2', 'v3', 'v4', 'v5', 'latest', 'beta', 'alpha', 'dev', 'staging', 'test', 'api', 'v1.0', 'v2.0', 'v3.0', 'v0', '2020', '2021', '2022', '2023', '2024', '2025', '2026'];
    const results = [];
    for (const v of versions) {
      const url = baseEndpoint.replace(/\/v\d+\//, `/${v}/`).replace(/\/api\//, `/api/${v}/`);
      try {
        const res = await this.send('GET', url);
        results.push({ version: v, url, status: res.status, exists: res.status < 404 });
        await this.sleep(this.delay);
      } catch { results.push({ version: v, url, error: true }); }
    }
    return results;
  }

  async detectSwagger(endpoint) {
    const paths = ['/swagger.json', '/swagger/v1/swagger.json', '/api/swagger.json', '/api/docs', '/api/v1/docs', '/docs', '/openapi.json', '/api/openapi.json', '/api/v1/openapi.json', '/swagger/index.html', '/swagger-ui.html', '/api/swagger-ui.html'];
    const results = [];
    for (const p of paths) {
      const url = new URL(p, endpoint).href;
      try {
        const res = await this.send('GET', url);
        results.push({ path: p, status: res.status, exists: res.status < 404, bodyHint: res.body.slice(0, 100) });
        await this.sleep(this.delay);
      } catch { results.push({ path: p, error: true }); }
    }
    return results;
  }

  async testBoundaryOverflow(endpoint, paramName) {
    const payloads = ['A'.repeat(10000), 'A'.repeat(100000), 'A'.repeat(500000), 'A'.repeat(1000000)];
    const results = [];
    for (const payload of payloads) {
      try {
        const res = await this.send('POST', endpoint, {
          body: this.buildBody({ [paramName]: payload }),
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });
        results.push({ size: payload.length, status: res.status, handled: res.status < 500 });
        await this.sleep(this.delay);
      } catch { results.push({ size: payload.length, error: true }); }
    }
    return results;
  }

  async testChunkedEncoding(endpoint) {
    const http = require('http');
    const parsed = new URL(endpoint);
    return new Promise((resolve) => {
      const req = http.request({
        hostname: parsed.hostname, port: parsed.port || 80, path: parsed.pathname,
        method: 'POST', headers: { 'Transfer-Encoding': 'chunked', 'Content-Type': 'application/x-www-form-urlencoded' }
      }, (res) => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => resolve({ status: res.statusCode, body: body.slice(0, 100) }));
      });
      req.write('5\r\nhello\r\n0\r\n\r\n');
      req.end();
    });
  }

  async testCompressionBomb(endpoint) {
    const zlib = require('zlib');
    const bomb = Buffer.alloc(1024 * 1024 * 10, 'A');
    const compressed = zlib.gzipSync(bomb);
    const results = [];
    try {
      const res = await this.send('POST', endpoint, {
        body: compressed,
        headers: { 'Content-Type': 'application/gzip', 'Content-Encoding': 'gzip' }
      });
      results.push({ size: bomb.length, compressedSize: compressed.length, status: res.status });
    } catch { results.push({ size: bomb.length, error: true }); }
    return results;
  }

  async testPaginationAbuse(endpoint, paramName = 'page') {
    const pages = [1, -1, 0, 999999, 'a', null, '1; DROP TABLE', '1e10', Number.MAX_SAFE_INTEGER];
    const results = [];
    for (const p of pages) {
      const url = new URL(endpoint);
      url.searchParams.set(paramName, String(p));
      try {
        const res = await this.send('GET', url.href);
        results.push({ page: p, status: res.status, bodyLength: res.bodyLength, anomaly: res.status === 500 || res.bodyLength > 1000000 });
        await this.sleep(this.delay);
      } catch { results.push({ page: p, error: true }); }
    }
    return results;
  }

  async fullAPIScan(endpoint) {
    console.log(`[APIFuzzer] Full API scan: ${endpoint}`);
    const results = {
      baseline: await this.scan(endpoint),
      graphQL: await this.fuzzGraphQL(endpoint),
      versions: await this.fuzzAPIVersions(endpoint),
      swagger: await this.detectSwagger(endpoint),
      pagination: await this.testPaginationAbuse(endpoint),
      chunked: await this.testChunkedEncoding(endpoint)
    };
    return results;
  }
}

module.exports = { APIFuzzer };
