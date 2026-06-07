class CSRFTester {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  async extractCSRFToken(formSelector = 'form') {
    return this.page.evaluate((sel) => {
      const form = document.querySelector(sel);
      if (!form) return null;
      const csrfCandidates = [];
      form.querySelectorAll('input[type="hidden"]').forEach(input => {
        const name = input.name.toLowerCase();
        if (/csrf|token|_token|authenticity|xsrf|nonce|__request|__anti/i.test(name)) {
          csrfCandidates.push({ name: input.name, value: input.value });
        }
      });
      return { action: form.action, method: form.method, tokens: csrfCandidates };
    }, formSelector);
  }

  async testCSRFTokenStrength() {
    const tokens = await this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('input[type="hidden"]').forEach(input => {
        const name = input.name.toLowerCase();
        if (/csrf|token|_token|authenticity|xsrf|nonce/i.test(name)) {
          results.push({ name: input.name, value: input.value });
        }
      });
      return results;
    });
    const findings = [];
    for (const token of tokens) {
      if (!token.value || token.value.length < 16) findings.push({ name: token.name, value: token.value, issue: 'Short or empty CSRF token', severity: 'HIGH' });
      if (/^\d+$/.test(token.value)) findings.push({ name: token.name, issue: 'Numeric CSRF token — predictable', severity: 'HIGH' });
      if (token.value === token.name) findings.push({ name: token.name, issue: 'CSRF token equals its name — placeholder', severity: 'CRITICAL' });
      const decoded = Buffer.from(token.value, 'base64').toString('utf-8').replace(/[^a-zA-Z0-9@.:\-_]/g, '');
      if (decoded.includes('@') || decoded.includes(':')) findings.push({ name: token.name, issue: `CSRF token may encode user data: ${decoded.slice(0, 30)}`, severity: 'HIGH' });
    }
    if (!tokens.length) findings.push({ issue: 'No CSRF tokens found in forms', severity: 'HIGH' });
    this.findings.push(...findings);
    return { tokens, findings, vulnerable: findings.length > 0 };
  }

  async testCSRFTokenReuse() {
    const token1 = await this.extractCSRFToken();
    if (!token1?.tokens?.[0]) return { error: 'No CSRF token to test' };
    const firstToken = token1.tokens[0].value;
    await this.page.goto(this.page.url(), { waitUntil: 'networkidle' });
    const token2 = await this.extractCSRFToken();
    if (!token2?.tokens?.[0]) return { error: 'Could not extract second token' };
    const same = firstToken === token2.tokens[0].value;
    this.findings.push({ test: 'token-reuse', same, issue: same ? 'CSRF token does not change between requests — replayable' : 'Token rotates', severity: same ? 'CRITICAL' : 'INFO' });
    return { tokenReused: same, firstToken: firstToken.slice(0, 20), secondToken: token2.tokens[0].value.slice(0, 20) };
  }

  async testSameSiteCookies() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const cookie of cookies) {
      if (!cookie.sameSite || cookie.sameSite === 'None') {
        findings.push({ name: cookie.name, sameSite: cookie.sameSite || 'not set', issue: 'SameSite not set or None — CSRF via cross-site request', severity: 'MEDIUM' });
      } else if (cookie.sameSite === 'Lax' && (cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('token'))) {
        findings.push({ name: cookie.name, sameSite: 'Lax', issue: 'Session cookie with SameSite=Lax — vulnerable to GET-based CSRF', severity: 'MEDIUM' });
      }
    }
    this.findings.push(...findings);
    return { findings, vulnerable: findings.length > 0 };
  }

  async testCORSMisconfiguration(origin) {
    const testOrigins = [
      'https://evil.com', 'https://attacker.com', 'null',
      'https://sub.evil.com', 'https://evil.com:443',
      'https://evilcompany.com', 'http://evil.com'
    ];
    if (origin) testOrigins.unshift(origin);
    const results = [];
    for (const testOrigin of testOrigins) {
      const corsResult = await this.page.evaluate(async (origin) => {
        try {
          const resp = await fetch(window.location.origin + '/api/cors-test', {
            method: 'OPTIONS',
            headers: { 'Origin': origin, 'Access-Control-Request-Method': 'GET' }
          }).catch(() => null);
          if (!resp) return { origin, cors: false, error: 'fetch failed' };
          const allowOrigin = resp.headers.get('Access-Control-Allow-Origin');
          const allowCredentials = resp.headers.get('Access-Control-Allow-Credentials');
          return { origin, cors: !!allowOrigin, allowOrigin, allowCredentials, status: resp.status };
        } catch (e) { return { origin, cors: false, error: e.message }; }
      }, testOrigin);
      results.push(corsResult);
    }
    const vulnerable = results.filter(r => r.cors);
    if (vulnerable.length) {
      this.findings.push({ type: 'cors', count: vulnerable.length, severity: 'HIGH' });
    }
    return { testedOrigins: testOrigins.length, vulnerable: vulnerable.length, results: vulnerable };
  }

  async testGETDowngrade(originalMethod) {
    if (originalMethod !== 'POST') return { error: 'Not a POST endpoint' };
    const currentUrl = this.page.url();
    const result = await this.page.evaluate(async (url) => {
      try {
        const resp = await fetch(url, { method: 'GET', credentials: 'include' });
        return { status: resp.status, success: resp.status < 400, bodyLength: (await resp.text()).length };
      } catch (e) { return { error: e.message }; }
    }, currentUrl);
    if (result.success) {
      this.findings.push({ type: 'get-downgrade', original: 'POST', downgradedTo: 'GET', issue: 'POST endpoint accepts GET — CSRF via <img>/<script> tag', severity: 'CRITICAL' });
    }
    return result;
  }

  async testJSONP() {
    const jsonpEndpoints = await this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script[src]');
      const jsonp = [];
      scripts.forEach(s => {
        if (s.src.includes('callback=') || s.src.includes('jsonp=') || s.src.includes('format=jsonp')) jsonp.push(s.src);
      });
      return jsonp;
    });
    if (jsonpEndpoints.length) this.findings.push({ type: 'jsonp', count: jsonpEndpoints.length, issue: 'JSONP endpoints found — potential data exfiltration via CSRF', severity: 'MEDIUM' });
    return jsonpEndpoints;
  }

  async testAntiCSRFValidation(tokenName, tokenValue) {
    const tests = [
      { name: 'Remove token', modify: (formBody) => formBody.replace(new RegExp(`&?${tokenName}=[^&]*`, 'g'), '') },
      { name: 'Empty token', modify: (formBody) => formBody.replace(new RegExp(`${tokenName}=[^&]*`), `${tokenName}=`) },
      { name: 'Wrong token', modify: (formBody) => formBody.replace(new RegExp(`${tokenName}=[^&]*`), `${tokenName}=INVALID_TOKEN`) },
      { name: 'Old token', modify: (formBody) => formBody.replace(new RegExp(`${tokenName}=[^&]*`), `${tokenName}=${tokenValue}`) }
    ];
    const results = [];
    for (const test of tests) {
      const modified = test.modify(`&${tokenName}=${tokenValue}`);
      results.push({ test: test.name, modifiedToken: modified });
    }
    return results;
  }

  generatePoC(method, action, params) {
    const fields = Object.entries(params).map(([k, v]) => `    <input type="hidden" name="${k.replace(/"/g, '&quot;')}" value="${v.replace(/"/g, '&quot;')}">`).join('\n');
    const html = method === 'GET' ? `<a href="${action}?${Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}">Click me</a>

<script>window.location.href = "${action}?${Object.entries(params).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&')}";</script>` : `<form action="${action}" method="${method}">
${fields}
  <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>`;
    return `<!DOCTYPE html>
<html>
<body>
${html}
</body>
</html>`;
  }

  async fullScan(url) {
    console.log('[CSRFTester] Starting CSRF scan...');
    await this.page.goto(url, { waitUntil: 'networkidle' });
    const results = {
      tokenStrength: await this.testCSRFTokenStrength(),
      sameSite: await this.testSameSiteCookies(),
      jsonp: await this.testJSONP()
    };
    const forms = await this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('form')).map(f => ({
        action: f.action,
        method: f.method,
        id: f.id,
        fields: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({ name: i.name, type: i.type }))
      }));
    });
    results.forms = forms;
    return results;
  }

  async testCustomHeaderValidation(endpoint) {
    const headers = ['X-CSRF-Token', 'X-XSRF-Token', 'X-Requested-By', 'X-Requested-With', 'X-CSRF-Header', 'X-Auth-Token'];
    const results = [];
    for (const header of headers) {
      try {
        const res = await fetch(endpoint, { method: 'POST', headers: { [header]: 'test' } });
        results.push({ header, status: res.status, accepted: res.status < 400 });
      } catch { results.push({ header, error: true }); }
    }
    return results;
  }

  async testDoubleSubmitCookie() {
    const cookies = await this.page.context().cookies();
    const csrfCookies = cookies.filter(c => /csrf|xsrf|token/i.test(c.name));
    const findings = [];
    for (const c of csrfCookies) {
      const body = await this.page.evaluate(async (name, value) => {
        try { const r = await fetch(window.location.href, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${name}=${value}` }); return r.status; } catch { return 0; }
      }, c.name, c.value);
      if (body < 400) findings.push({ cookie: c.name, issue: 'Double-submit cookie pattern — CSRF token equals cookie value', severity: 'HIGH' });
    }
    this.findings.push(...findings);
    return findings;
  }

  async testStateParameter(url) {
    const parsed = new URL(url);
    const stateParam = parsed.searchParams.get('state');
    if (!stateParam) return { statePresent: false };
    const findings = [];
    if (stateParam.length < 16) findings.push({ issue: 'OAuth state parameter too short: ' + stateParam.length + ' chars', severity: 'HIGH' });
    if (/^[a-z]+$/i.test(stateParam)) findings.push({ issue: 'OAuth state parameter non-random pattern', severity: 'HIGH' });
    if (stateParam === this.page.url().split('?')[0]) findings.push({ issue: 'OAuth state parameter is current URL — CSRF predictable', severity: 'CRITICAL' });
    this.findings.push(...findings);
    return { statePresent: true, findings };
  }

  async testCORSWithCredentials(endpoint) {
    const results = [];
    const origins = ['https://evil.com', 'null', 'https://attacker.net', 'http://localhost:8080'];
    for (const origin of origins) {
      try {
        const res = await fetch(endpoint, { method: 'GET', credentials: 'include', headers: { 'Origin': origin } });
        const acao = res.headers.get('Access-Control-Allow-Origin');
        const acac = res.headers.get('Access-Control-Allow-Credentials');
        if (acao && acac === 'true') results.push({ origin, acao, vulnerable: true });
      } catch {}
    }
    if (results.length) this.findings.push({ type: 'cors-credentials', count: results.length, severity: 'CRITICAL' });
    return results;
  }

  async testIdempotency(endpoint) {
    const results = [];
    for (let i = 0; i < 3; i++) {
      try {
        const res = await fetch(endpoint, { method: 'DELETE' });
        results.push({ attempt: i + 1, status: res.status });
      } catch { results.push({ attempt: i + 1, error: true }); }
    }
    const uniqueStatuses = [...new Set(results.map(r => r.status))];
    if (uniqueStatuses.length > 1) this.findings.push({ type: 'non-idempotent', endpoint, issue: 'DELETE/PUT not idempotent', severity: 'LOW' });
    return results;
  }

  async testRefererCheck() {
    const results = [];
    const referers = ['https://evil.com', 'https://evil.com/page', 'http://evil.com', ''];
    for (const ref of referers) {
      try {
        const res = await fetch(this.page.url(), { method: 'POST', headers: { 'Referer': ref } });
        results.push({ referer: ref || '(none)', status: res.status, blocked: res.status === 403 || res.status === 401 });
      } catch { results.push({ referer: ref, error: true }); }
    }
    return results;
  }

  async testJSONCsrf(endpoint) {
    const results = [];
    const bodies = [{}, { '': '' }, JSON.stringify({})];
    for (const body of bodies) {
      try {
        const res = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: typeof body === 'string' ? body : JSON.stringify(body) });
        results.push({ contentType: 'application/json', status: res.status });
      } catch { results.push({ contentType: 'application/json', error: true }); }
    }
    return results;
  }

  async automatedPoC(method, action, params) {
    return `<!DOCTYPE html>
<html>
<body>
<form action="${action}" method="${method}">
${Object.entries(params).map(([k, v]) => `  <input type="hidden" name="${k}" value="${v}">`).join('\n')}
  <input type="submit" value="Submit">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>`;
  }

  async testLaxBypass(endpoint) {
    const methods = ['GET', 'POST'];
    const results = [];
    for (const m of methods) {
      const res = await fetch(endpoint, { method: m, credentials: 'include' });
      results.push({ method: m, status: res.status, cookiesSent: res.headers.get('Cookie') || 'no' });
    }
    return results;
  }

  async testXRequestedWith() {
    const res = await fetch(this.page.url(), { method: 'GET', headers: { 'X-Requested-With': 'XMLHttpRequest' } });
    return { accepted: res.status < 400, status: res.status, header: 'X-Requested-With: XMLHttpRequest' };
  }

  async testPreflightBypass(endpoint) {
    const methods = ['GET', 'POST', 'PUT', 'DELETE'];
    const results = [];
    for (const m of methods) {
      try {
        const res = await fetch(endpoint, { method: m, mode: 'no-cors' });
        results.push({ method: m, status: res.status, noCORSSuccess: res.type === 'opaque' });
      } catch { results.push({ method: m, error: true }); }
    }
    return results;
  }
}

module.exports = { CSRFTester };
