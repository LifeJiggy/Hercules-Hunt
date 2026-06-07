const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

class EndpointCollector {
  constructor(options = {}) {
    this.timeout = options.timeout || 15000;
    this.userAgent = options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)';
    this.outputDir = options.outputDir || 'output/endpoints';
    this.collected = new Map();
  }

  async fetchUrl(targetUrl) {
    const isHttps = targetUrl.startsWith('https:');
    const lib = isHttps ? https : http;
    return new Promise((resolve, reject) => {
      const req = lib.get(targetUrl, {
        headers: { 'User-Agent': this.userAgent },
        timeout: this.timeout,
        rejectUnauthorized: false
      }, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString(),
            contentType: res.headers['content-type'] || ''
          });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.on('error', reject);
    });
  }

  extractFromJS(content, sourceUrl = '') {
    const endpoints = new Set();
    const patterns = [
      /(?:"|')(\/[a-zA-Z0-9_\-./?=&%]+)(?:"|')/g,
      /(?:"|')(https?:\/\/[a-zA-Z0-9_.\-/?=&%]+)(?:"|')/g,
      /(?:\/\/\s*|["'`])\/api\/[a-zA-Z0-9_\-./?=&%]+(?=["'`])/g,
      /(?:\/\/\s*|["'`])https?:\/\/[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_\-./?=&%]*)?(?=["'`])/g,
      /fetch\(["'`]([^"'`]+)["'`]\)/g,
      /axios\.(?:get|post|put|patch|delete|request)\(["'`]([^"'`]+)["'`]\)/g,
      /\$\.(?:get|post|ajax)\(["'`]([^"'`]+)["'`]\)/g,
      /XMLHttpRequest\.open\(["'`][A-Z]+["'`],\s*["'`]([^"'`]+)["'`]\)/g,
      /url:\s*["'`]([^"'`]+)["'`]/g,
      /path:\s*["'`]([^"'`]+)["'`]/g,
      /endpoint:\s*["'`]([^"'`]+)["'`]/g,
      /route:\s*["'`]([^"'`]+)["'`]/g,
      /href=["'`]([^"'`]+)["'`]/g,
      /action=["'`]([^"'`]+)["'`]/g,
      /src=["'`]([^"'`]+)["'`]/g,
      /["'`]([^"'`]*\/api\/[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/v\d+(?:\/\d+)?[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/graphql[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/rest[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/oauth[^"'`]*)["'`]/g,
      /["'`]([^"'`]*\/callback[^"'`]*)["'`]/g
    ];

    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let ep = match[1] || match[0];
        ep = ep.replace(/^["'`]|["'`]$/g, '').trim();
        if (ep && ep.length > 2 && !ep.startsWith('data:') && !ep.startsWith('javascript:')) {
          if (ep.startsWith('/') && sourceUrl) {
            try {
              const base = new URL(sourceUrl);
              ep = `${base.origin}${ep}`;
            } catch {}
          }
          endpoints.add(ep);
        }
      }
    }
    return Array.from(endpoints).sort();
  }

  extractSecrets(content) {
    const secrets = new Set();
    const patterns = [
      { name: 'AWS Key', regex: /AKIA[0-9A-Z]{16}/g },
      { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
      { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z\-_]{10,}/g },
      { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/g },
      { name: 'Bearer Token', regex: /bearer\s+[a-zA-Z0-9\-_.]+/gi },
      { name: 'API Key Generic', regex: /api[_-]?key["'\s:=]+([a-zA-Z0-9\-_.]{16,64})/gi },
      { name: 'Password', regex: /password["'\s:=]+([^"'&\s,]{6,})/gi },
      { name: 'Secret', regex: /secret["'\s:=]+([^"'&\s,]{8,})/gi },
      { name: 'Auth Token', regex: /auth[_-]?token["'\s:=]+([^"'&\s,]{8,})/gi },
      { name: 'Private Key', regex: /-----BEGIN\s?(RSA|EC|DSA|OPENSSH)?\s?PRIVATE\s?KEY-----/g },
      { name: 'Firebase URL', regex: /[a-zA-Z0-9\-_]+\.firebaseio\.com/g },
      { name: 'S3 Bucket', regex: /[a-zA-Z0-9\-_.]+\.s3\.amazonaws\.com/g },
      { name: 'GraphQL Endpoint', regex: /https?:\/\/[^"'\s,]+?\/graphql/g },
      { name: 'Webhook URL', regex: /https?:\/\/hooks\.slack\.com\/[a-zA-Z0-9\/]+/g },
      { name: 'MongoDB URI', regex: /mongodb(?:\+srv)?:\/\/[a-zA-Z0-9\-_.:@/?&]+/g }
    ];
    for (const { name, regex } of patterns) {
      let match;
      while ((match = regex.exec(content)) !== null) {
        secrets.add(JSON.stringify({ type: name, value: match[0].slice(0, 120) }));
      }
    }
    return Array.from(secrets).map(s => JSON.parse(s));
  }

  async fetchSourceMap(jsUrl) {
    try {
      const content = await this.fetchUrl(jsUrl);
      const sourceMapMatch = content.body.match(/\/\/#\s*sourceMappingURL=(.+)/);
      if (!sourceMapMatch) return null;
      const smUrl = new URL(sourceMapMatch[1], jsUrl).href;
      const smContent = await this.fetchUrl(smUrl);
      return JSON.parse(smContent.body);
    } catch { return null; }
  }

  async analyzeScript(scriptUrl) {
    try {
      const content = await this.fetchUrl(scriptUrl);
      const endpoints = this.extractFromJS(content.body, scriptUrl);
      const secrets = this.extractSecrets(content.body);
      const sourceMap = await this.fetchSourceMap(scriptUrl);
      let sourceMapEndpoints = [];
      if (sourceMap && sourceMap.sources) {
        sourceMapEndpoints = sourceMap.sources.filter(s => !s.includes('node_modules'));
      }
      const result = {
        url: scriptUrl,
        size: content.body.length,
        endpointsFound: endpoints.length,
        secretsFound: secrets.length,
        endpoints,
        secrets,
        sourceMapSources: sourceMapEndpoints,
        hasSourceMap: !!sourceMap
      };
      this.collected.set(scriptUrl, result);
      return result;
    } catch (e) {
      return { url: scriptUrl, error: e.message };
    }
  }

  async discoverScripts(pageUrl) {
    const content = await this.fetchUrl(pageUrl);
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const scripts = [];
    const pageUrls = [];
    let match;
    while ((match = scriptRegex.exec(content.body)) !== null) {
      let src = match[1];
      try {
        src = new URL(src, pageUrl).href;
        pageUrls.push(src);
        scripts.push({ src, tag: match[0] });
      } catch {}
    }
    const inlineRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    let inlineIdx = 0;
    while ((inlineMatch = inlineRegex.exec(content.body)) !== null) {
      const js = inlineMatch[1];
      if (js.length > 50) {
        const ep = this.extractFromJS(js);
        scripts.push({ src: `inline:${inlineIdx++}`, length: js.length, endpoints: ep });
      }
    }
    return { pageUrl, scripts, pageEndpoints: pageUrls };
  }

  async recursiveCrawlJS(startUrl, depth = 1) {
    const visited = new Set();
    const queue = [{ url: startUrl, depth: 0 }];
    const results = [];
    while (queue.length > 0) {
      const { url, depth: currentDepth } = queue.shift();
      if (visited.has(url) || currentDepth > depth) continue;
      visited.add(url);
      try {
        const result = await this.analyzeScript(url);
        results.push(result);
        if (currentDepth < depth) {
          for (const ep of result.endpoints) {
            if (ep.endsWith('.js') && !visited.has(ep) && queue.length < 50) {
              queue.push({ url: ep, depth: currentDepth + 1 });
            }
          }
        }
      } catch { results.push({ url, error: 'Failed' }); }
    }
    return results;
  }

  exportResults(format = 'json') {
    fs.mkdirSync(this.outputDir, { recursive: true });
    const data = Array.from(this.collected.values());
    const allEndpoints = [...new Set(data.flatMap(d => d.endpoints || []))].sort();
    const allSecrets = data.flatMap(d => d.secrets || []);
    if (format === 'json') {
      const filePath = path.join(this.outputDir, 'endpoints.json');
      fs.writeFileSync(filePath, JSON.stringify({ scripts: data, allEndpoints, allSecrets }, null, 2));
      return filePath;
    }
    const mdPath = path.join(this.outputDir, 'endpoints.md');
    const md = [`# Collected Endpoints\n`, `Total scripts: ${data.length}`, `Total endpoints: ${allEndpoints.length}`, `Total secrets: ${allSecrets.length}\n`];
    md.push(`## All Endpoints (${allEndpoints.length})\n`);
    allEndpoints.forEach(ep => md.push(`- \`${ep}\``));
    md.push(`\n## Secrets Found (${allSecrets.length})\n`);
    allSecrets.forEach(s => md.push(`- ${s.type}: \`${s.value}\``));
    fs.writeFileSync(mdPath, md.join('\n'));
    return mdPath;
  }
}

module.exports = { EndpointCollector };
