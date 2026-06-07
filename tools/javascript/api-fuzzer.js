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
}

module.exports = { APIFuzzer };
