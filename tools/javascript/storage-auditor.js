class StorageAuditor {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  sensitivePatterns = [
    { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/ },
    { name: 'Session Token', pattern: /(session|sid|token|auth)[^=]*=(?!false|null|undefined|0)\s*['"]?[a-zA-Z0-9\-_]{20,}/i },
    { name: 'API Key', pattern: /(api[_-]?key|apikey|api_secret)[^=]*=['"]?[a-zA-Z0-9\-_]{10,}/i },
    { name: 'Bearer Token', pattern: /bearer\s+[a-zA-Z0-9\-_.]+/i },
    { name: 'Password', pattern: /password\s*[:=]\s*['"]?[^'"\s]{4,}/i },
    { name: 'Email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
    { name: 'Phone', pattern: /\+?\d{7,15}/ },
    { name: 'SSN/ID', pattern: /\b\d{3}-\d{2}-\d{4}\b/ },
    { name: 'Credit Card', pattern: /\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/ },
    { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/ },
    { name: 'Private Key', pattern: /-----BEGIN\sPRIVATE\sKEY-----/ },
    { name: 'Google API Key', pattern: /AIza[0-9A-Za-z\-_]{35}/ },
    { name: 'Slack Token', pattern: /xox[baprs]-[0-9A-Za-z\-_]{10,}/ },
    { name: 'Mongo URI', pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<]+/ },
    { name: 'OAuth Token', pattern: /ya29\.[a-zA-Z0-9\-_]+/ },
    { name: 'Firebase URL', pattern: /[a-zA-Z0-9\-_]+\.firebaseio\.com/ },
    { name: 'GraphQL Endpoint', pattern: /https?:\/\/[^"'\s]+?\/graphql/ }
  ];

  async auditLocalStorage() {
    return this.page.evaluate(() => {
      const data = {};
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        data[k] = localStorage.getItem(k);
      }
      return data;
    });
  }

  async auditSessionStorage() {
    return this.page.evaluate(() => {
      const data = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        data[k] = sessionStorage.getItem(k);
      }
      return data;
    });
  }

  async auditIndexedDB() {
    return this.page.evaluate(async () => {
      const databases = await indexedDB.databases?.() || [];
      const results = [];
      for (const dbInfo of databases) {
        const db = await new Promise((resolve, reject) => {
          const req = indexedDB.open(dbInfo.name);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const stores = Array.from(db.objectStoreNames);
        const storeData = {};
        for (const storeName of stores) {
          const tx = db.transaction(storeName, 'readonly');
          const store = tx.objectStore(storeName);
          storeData[storeName] = await new Promise((resolve) => {
            const records = [];
            const cursor = store.openCursor();
            cursor.onsuccess = (e) => {
              const c = e.target.result;
              if (c) { records.push({ key: c.key, value: c.value }); c.continue(); }
              else resolve(records);
            };
          });
        }
        db.close();
        results.push({ name: dbInfo.name, version: dbInfo.version, stores: storeData, recordCount: Object.values(storeData).reduce((a, s) => a + s.length, 0) });
      }
      return results;
    }).catch(() => []);
  }

  async auditCacheAPI() {
    return this.page.evaluate(async () => {
      if (typeof caches === 'undefined') return [];
      const cacheNames = await caches.keys();
      const results = [];
      for (const name of cacheNames) {
        const cache = await caches.open(name);
        const requests = await cache.keys();
        results.push({ name, cacheSize: requests.length, urls: requests.map(r => r.url).slice(0, 50) });
      }
      return results;
    }).catch(() => []);
  }

  async auditServiceWorker() {
    return this.page.evaluate(() => {
      if (typeof navigator.serviceWorker === 'undefined') return { registered: false };
      return {
        registered: true,
        controller: navigator.serviceWorker.controller?.scriptURL || null,
        scope: navigator.serviceWorker.controller?.scope || null
      };
    }).catch(() => ({ registered: false }));
  }

  async detectSensitiveData(data, source) {
    const findings = [];
    for (const [key, value] of Object.entries(data)) {
      if (!value || typeof value !== 'string') continue;
      const combined = `${key}: ${value}`;
      for (const { name, pattern } of this.sensitivePatterns) {
        const match = combined.match(pattern);
        if (match) {
          const truncated = match[0].length > 80 ? match[0].slice(0, 80) + '...' : match[0];
          findings.push({ type: name, key, source, value: truncated, severity: name.includes('Key') || name.includes('Token') || name.includes('Password') || name.includes('Secret') ? 'CRITICAL' : 'HIGH' });
        }
      }
    }
    return findings;
  }

  async checkCookieJar() {
    const cookies = await this.page.context().cookies();
    const findings = [];
    for (const cookie of cookies) {
      const sensitiveKeys = ['session', 'token', 'auth', 'sid', 'jwt', 'access', 'refresh', 'secret', 'api', 'key', 'bearer', 'credentials', 'csrf', 'xsrf', 'nonce', 'state', 'code', 'id_token'];
      const isSensitive = sensitiveKeys.some(k => cookie.name.toLowerCase().includes(k));
      if (isSensitive && !cookie.httpOnly) findings.push({ cookie: cookie.name, issue: 'Sensitive cookie without HttpOnly', severity: 'HIGH' });
      if (isSensitive && !cookie.secure) findings.push({ cookie: cookie.name, issue: 'Sensitive cookie without Secure flag', severity: 'HIGH' });
      if (isSensitive && cookie.value.length > 50) findings.push({ cookie: cookie.name, issue: `Long sensitive cookie value (${cookie.value.length} chars) — may contain encoded data`, severity: 'MEDIUM' });
      const decoded = Buffer.from(cookie.value, 'base64').toString('utf-8').replace(/[^a-zA-Z0-9@.:\-_]/g, '');
      if (isSensitive && cookie.value.match(/^[a-zA-Z0-9+/=]{20,}$/) && decoded.includes('@')) findings.push({ cookie: cookie.name, issue: `Base64-encoded cookie contains email: ${decoded.slice(0, 40)}`, severity: 'CRITICAL' });
    }
    return findings;
  }

  async checkRemnantData() {
    return this.page.evaluate(() => {
      const remnants = [];
      const body = document.body.innerHTML;
      const dataAttrs = body.match(/data-[a-zA-Z]+="[^"]{20,}"/g);
      if (dataAttrs) remnants.push({ type: 'data-attributes', count: dataAttrs.length, samples: dataAttrs.slice(0, 5) });
      const comments = body.match(/<!--[\s\S]{20,}?-->/g);
      if (comments) remnants.push({ type: 'html-comments', count: comments.length, samples: comments.slice(0, 5).map(c => c.slice(0, 100)) });
      const metaContent = [];
      document.querySelectorAll('meta[name="description"], meta[name="keywords"]').forEach(m => {
        if (m.getAttribute('content')?.length > 0) metaContent.push({ name: m.getAttribute('name'), content: m.getAttribute('content') });
      });
      if (metaContent.length) remnants.push({ type: 'meta-tags', data: metaContent });
      const scripts = document.querySelectorAll('script');
      scripts.forEach(s => {
        const src = s.src || 'inline';
        if (s.textContent && s.textContent.includes('CONFIG') || s.textContent?.includes('SECRET') || s.textContent?.includes('PASSWORD')) {
          remnants.push({ type: 'script-leak', src, snippet: s.textContent.slice(0, 200) });
        }
      });
      return remnants;
    });
  }

  async fullAudit() {
    console.log('[StorageAuditor] Auditing all client-side storage...');
    const results = {
      localStorage: await this.auditLocalStorage(),
      sessionStorage: await this.auditSessionStorage(),
      cookies: await this.auditCookies(),
      indexedDB: await this.auditIndexedDB(),
      cacheAPI: await this.auditCacheAPI(),
      serviceWorker: await this.auditServiceWorker(),
      remnants: await this.checkRemnantData()
    };
    const lsFindings = await this.detectSensitiveData(results.localStorage, 'localStorage');
    const ssFindings = await this.detectSensitiveData(results.sessionStorage, 'sessionStorage');
    const cookieFindings = await this.checkCookieJar();
    this.findings.push(...lsFindings, ...ssFindings, ...cookieFindings);
    results.sensitiveData = { localStorage: lsFindings, sessionStorage: ssFindings, cookies: cookieFindings };
    results.summary = {
      localStorageKeys: Object.keys(results.localStorage).length,
      sessionStorageKeys: Object.keys(results.sessionStorage).length,
      cookies: results.cookies?.length || 0,
      indexedDBDatabases: results.indexedDB.length,
      cacheAPICaches: results.cacheAPI.length,
      serviceWorker: results.serviceWorker.registered,
      sensitiveFindings: this.findings.length,
      remnantsFound: results.remnants.length
    };
    return results;
  }

  async auditCookies() {
    return this.page.context().cookies();
  }
}

module.exports = { StorageAuditor };
