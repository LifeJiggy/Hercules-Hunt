class SessionHijacker {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  async auditCookies() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const cookie of cookies) {
      const issues = [];
      if (!cookie.httpOnly) issues.push('Missing HttpOnly flag — accessible via JavaScript');
      if (!cookie.secure) issues.push('Missing Secure flag — sent over HTTP');
      if (!cookie.sameSite || cookie.sameSite === 'None') issues.push('SameSite=None — vulnerable to CSRF');
      if (cookie.sameSite === 'Lax' && cookie.name.toLowerCase().includes('session')) issues.push('Session cookie with SameSite=Lax — CSRF on GET');
      if (cookie.expires && (cookie.expires - Date.now()) > 86400000 * 365) issues.push('Cookie expires >1 year — excessive session lifetime');
      if (cookie.domain && cookie.domain.startsWith('.')) issues.push('Wildcard domain cookie — shared across subdomains');
      if (cookie.path === '/') issues.push('Root path — accessible on all endpoints');
      if (issues.length) {
        findings.push({ name: cookie.name, domain: cookie.domain, path: cookie.path, issues, severity: issues.length > 2 ? 'HIGH' : issues.length > 1 ? 'MEDIUM' : 'LOW' });
      }
    }
    this.findings.push(...findings);
    return { total: cookies.length, vulnerable: findings.length, findings };
  }

  async testSessionFixation(loginUrl, fixateUrl, loginCredentials) {
    const findings = [];
    const fixatedSessionId = 'FIXATED-SESSION-' + Date.now();
    await this.page.goto(fixateUrl || loginUrl, { waitUntil: 'networkidle' });
    await this.page.evaluate((sid) => {
      document.cookie = `sessionid=${sid}; path=/`;
      document.cookie = `JSESSIONID=${sid}; path=/`;
      document.cookie = `PHPSESSID=${sid}; path=/`;
      document.cookie = `sid=${sid}; path=/`;
      document.cookie = `token=${sid}; path=/`;
    }, fixatedSessionId);
    const preLoginCookies = await this.page.context().cookies();
    const preSessionCookie = preLoginCookies.find(c => c.name.toLowerCase().includes('session') || c.name.toLowerCase().includes('sid') || c.name.toLowerCase().includes('token'));
    if (loginCredentials) {
      await this.page.goto(loginUrl, { waitUntil: 'networkidle' });
      if (loginCredentials.usernameField) {
        await this.page.fill(loginCredentials.usernameField, loginCredentials.username);
        await this.page.fill(loginCredentials.passwordField, loginCredentials.password);
        if (loginCredentials.submitButton) {
          await Promise.all([
            this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {}),
            this.page.click(loginCredentials.submitButton)
          ]);
        }
      }
    }
    const postLoginCookies = await this.page.context().cookies();
    for (const pre of preLoginCookies) {
      const post = postLoginCookies.find(c => c.name === pre.name);
      if (post && pre.value === post.value && pre.value === fixatedSessionId) {
        findings.push({ cookie: pre.name, issue: 'Session ID persisted before and after login — SESSION FIXATION', severity: 'CRITICAL' });
      }
    }
    this.findings.push(...findings);
    return { fixatedSessionId, preLoginCookies, postLoginCookies, vulnerable: findings.length > 0, findings };
  }

  async checkSessionEntropy() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const cookie of cookies) {
      const value = cookie.value;
      if (!value || value.length < 16) {
        findings.push({ name: cookie.name, value: value?.slice(0, 20), issue: `Short session token (${value?.length || 0} chars) — low entropy`, severity: 'HIGH' });
        continue;
      }
      if (/^\d+$/.test(value)) findings.push({ name: cookie.name, issue: 'Numeric session ID — predictable', severity: 'HIGH' });
      else if (/^[a-z]+$/i.test(value) && value.length < 32) findings.push({ name: cookie.name, issue: 'Alphabetic session token — low entropy', severity: 'MEDIUM' });
      else if (value === value.toLowerCase() || value === value.toUpperCase()) findings.push({ name: cookie.name, issue: 'Non-mixed-case token — reduced entropy', severity: 'LOW' });
      if (value.includes(':')) findings.push({ name: cookie.name, issue: 'Session value contains colon — may encode username:timestamp', severity: 'MEDIUM' });
      const uniqueChars = new Set(value).size;
      const ratio = uniqueChars / value.length;
      if (ratio < 0.3) findings.push({ name: cookie.name, issue: `Low character diversity (${(ratio * 100).toFixed(0)}% unique) — biased token`, severity: 'LOW' });
    }
    this.findings.push(...findings);
    return findings;
  }

  async detectSessionInStorage() {
    const storage = await this.page.evaluate(() => {
      const ls = {};
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        ls[k] = localStorage.getItem(k);
      }
      const ss = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        ss[k] = sessionStorage.getItem(k);
      }
      return { localStorage: ls, sessionStorage: ss };
    });
    const findings = [];
    const sessionPatterns = [/session/i, /token/i, /jwt/i, /auth/i, /bearer/i, /sid/i, /access/i, /refresh/i, /credentials?/i, /api.?key/i, /secret/i];
    const check = (name, value, store) => {
      for (const pattern of sessionPatterns) {
        if (pattern.test(name) || pattern.test(value?.slice(0, 100))) {
          const truncated = value?.length > 80 ? value.slice(0, 80) + '...' : value;
          findings.push({ store, key: name, value: truncated, issue: `Session/credential in ${store}: ${name}`, severity: 'HIGH' });
          break;
        }
      }
    };
    Object.entries(storage.localStorage).forEach(([k, v]) => check(k, v, 'localStorage'));
    Object.entries(storage.sessionStorage).forEach(([k, v]) => check(k, v, 'sessionStorage'));
    this.findings.push(...findings);
    return { storage, findings, vulnerable: findings.length > 0 };
  }

  async checkInsecureTokenTransmission() {
    const urls = await this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('script[src], link[rel="stylesheet"], img[src], iframe[src]').forEach(el => {
        const src = el.src || el.href;
        if (src && src.startsWith('http:')) results.push({ element: el.tagName, url: src });
      });
      return results;
    });
    return { mixedContent: urls, count: urls.length };
  }

  async analyzeSessionTimeout() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const cookie of cookies) {
      if (cookie.name.toLowerCase().includes('session') || cookie.name.toLowerCase().includes('sid') || cookie.name.toLowerCase().includes('token')) {
        if (cookie.session) findings.push({ name: cookie.name, issue: 'Session cookie (no expiration) — session never expires', severity: 'MEDIUM' });
        else if (cookie.expires) {
          const maxAge = (cookie.expires - Date.now()) / 1000;
          if (maxAge > 86400 * 30) findings.push({ name: cookie.name, expiresIn: `${Math.round(maxAge / 3600)}h`, issue: `Excessive session lifetime (${Math.round(maxAge / 86400)} days)`, severity: 'LOW' });
        }
      }
    }
    return findings;
  }

  async fullSessionAudit(loginUrl, loginCredentials) {
    console.log('[SessionHijacker] Starting full session audit...');
    const results = {
      cookieAudit: await this.auditCookies(),
      entropyCheck: await this.checkSessionEntropy(),
      storageCheck: await this.detectSessionInStorage(),
      mixedContent: await this.checkInsecureTokenTransmission(),
      timeoutAnalysis: await this.analyzeSessionTimeout()
    };
    if (loginUrl) results.sessionFixation = await this.testSessionFixation(loginUrl, null, loginCredentials);
    const prioritized = this.findings.sort((a, b) => {
      const sev = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (sev[b.severity] || 0) - (sev[a.severity] || 0);
    });
    return { ...results, totalFindings: this.findings.length, prioritized };
  }

  async checkCookiePrefixes() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    const sensitive = cookies.filter(c => c.name.toLowerCase().includes('session') || c.name.toLowerCase().includes('token') || c.name.toLowerCase().includes('auth'));
    for (const c of sensitive) {
      if (!c.name.startsWith('__Secure-') && c.secure) findings.push({ name: c.name, issue: 'Secure cookie missing __Secure- prefix', severity: 'LOW' });
      if (!c.name.startsWith('__Host-') && c.secure && c.path === '/' && !c.domain.startsWith('.')) findings.push({ name: c.name, issue: 'Host-critical cookie missing __Host- prefix', severity: 'MEDIUM' });
    }
    this.findings.push(...findings);
    return findings;
  }

  async testConcurrentSessions() {
    const context2 = await this.page.context().browser().newContext();
    const page2 = await context2.newPage();
    await page2.goto(this.page.url(), { waitUntil: 'networkidle' });
    const cookies1 = await this.page.context().cookies();
    const cookies2 = await context2.cookies();
    const sharedActive = cookies1.some(c1 => cookies2.some(c2 => c2.name === c1.name && c2.value === c1.value));
    if (sharedActive) this.findings.push({ type: 'concurrent-session', issue: 'Same session active across browser contexts', severity: 'HIGH' });
    await context2.close();
    return { concurrentAllowed: sharedActive };
  }

  async testLogoutEffectiveness() {
    const preCookies = await this.page.context().cookies();
    await this.page.goto(this.page.url().replace(/\/[^/]*$/, '/logout'), { waitUntil: 'networkidle', timeout: 10000 }).catch(() => {});
    await this.page.evaluate(() => { document.cookie.split(';').forEach(c => { document.cookie = c.replace(/^ +/, '').replace(/=.*/, '=;expires=Thu, 01 Jan 2000 00:00:00 GMT;path=/'); }); });
    const postCookies = await this.page.context().cookies();
    const stillValid = postCookies.filter(pc => preCookies.some(pc2 => pc2.name === pc.name && pc2.value === pc.value));
    if (stillValid.length) this.findings.push({ type: 'logout-ineffective', count: stillValid.length, cookies: stillValid.map(c => c.name), issue: 'Cookies persist after logout — session not invalidated', severity: 'CRITICAL' });
    return { preCount: preCookies.length, postCount: postCookies.length, stillValid: stillValid.map(c => c.name) };
  }

  async analyzeRememberMe() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const c of cookies) {
      if (c.name.toLowerCase().includes('remember') || c.name.toLowerCase().includes('keep')) {
        if (c.expires && (c.expires - Date.now()) > 86400000 * 30) findings.push({ name: c.name, issue: 'Remember-me token expires >30 days — extended attack window', severity: 'HIGH' });
        if (!c.httpOnly) findings.push({ name: c.name, issue: 'Remember-me token not HttpOnly — XSS theft possible', severity: 'HIGH' });
        if (!c.secure) findings.push({ name: c.name, issue: 'Remember-me token not Secure — intercepted over HTTP', severity: 'HIGH' });
      }
    }
    this.findings.push(...findings);
    return findings;
  }

  async testCookieTossing() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    const domainGroups = {};
    for (const c of cookies) { const d = c.domain || ''; if (!domainGroups[d]) domainGroups[d] = []; domainGroups[d].push(c); }
    for (const [domain, domainCookies] of Object.entries(domainGroups)) {
      const nameCounts = {};
      domainCookies.forEach(c => { nameCounts[c.name] = (nameCounts[c.name] || 0) + 1; });
      for (const [name, count] of Object.entries(nameCounts)) {
        if (count > 1) findings.push({ domain, name, issue: `Cookie '${name}' has ${count} variants across paths — cookie tossing possible`, severity: 'HIGH' });
      }
    }
    this.findings.push(...findings);
    return findings;
  }

  async detectJWTInCookies() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const c of cookies) {
      if (c.value.match(/^eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+/)) {
        const payload = JSON.parse(Buffer.from(c.value.split('.')[1], 'base64url').toString());
        findings.push({ name: c.name, issue: 'JWT stored in cookie', severity: 'HIGH', payload: { sub: payload.sub, exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : null } });
        if (!c.httpOnly) findings.push({ name: c.name, issue: 'JWT cookie without HttpOnly — XSS can steal it', severity: 'CRITICAL' });
        if (!c.secure) findings.push({ name: c.name, issue: 'JWT cookie without Secure — sent over HTTP', severity: 'HIGH' });
      }
    }
    this.findings.push(...findings);
    return findings;
  }

  async scanBatch(urls) {
    const allResults = [];
    for (const url of urls) {
      await this.page.goto(url, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
      const result = await this.fullSessionAudit(url);
      allResults.push({ url, ...result });
    }
    return allResults;
  }

  async exportFindings(filePath = 'output/session-audit.json') {
    const fs = require('fs');
    const path = require('path');
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(this.findings, null, 2));
    const mdPath = filePath.replace('.json', '.md');
    const lines = ['# Session Hijacker Findings', '', `Total: ${this.findings.length}`, ''];
    const grouped = {}; this.findings.forEach(f => { const s = f.severity || 'INFO'; if (!grouped[s]) grouped[s] = []; grouped[s].push(f); });
    for (const [sev, items] of Object.entries({ CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] })) {
      const found = grouped[sev] || [];
      if (!found.length) continue;
      lines.push(`## ${sev} (${found.length})`, '');
      found.forEach(f => lines.push(`- ${f.issue || f.type}: ${f.name || f.detail || ''}`));
      lines.push('');
    }
    fs.writeFileSync(mdPath, lines.join('\n'));
    return { json: filePath, md: mdPath };
  }

  async setVerbose(enabled) { this.verbose = enabled; }
  async setRetry(count) { this.retryCount = count; }
  async checkLocalStorageCookieMirror() {
    const storage = await this.page.evaluate(() => ({ ...localStorage }));
    const findings = [];
    for (const [key, val] of Object.entries(storage)) {
      if (key.toLowerCase().includes('cookie') || key.toLowerCase().includes('session')) findings.push({ key, length: val.length, issue: `Session data mirrored in localStorage: ${key}`, severity: 'MEDIUM' });
    }
    this.findings.push(...findings);
    return findings;
  }
}

module.exports = { SessionHijacker };
