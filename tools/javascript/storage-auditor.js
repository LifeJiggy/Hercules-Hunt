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

  async auditWebSQL() {
    return this.page.evaluate(() => {
      if (typeof openDatabase === 'undefined') return { supported: false };
      const results = [];
      try {
        const db = openDatabase('__jiggy_audit__', '1.0', 'Jiggy Audit', 2 * 1024 * 1024);
        db.transaction(tx => {
          tx.executeSql('SELECT name FROM sqlite_master WHERE type=\'table\'', [], (tx, r) => {
            for (let i = 0; i < r.rows.length; i++) results.push({ table: r.rows.item(i).name });
          });
        });
      } catch {}
      return { supported: true, databases: results };
    });
  }

  async auditFileSystem() {
    return this.page.evaluate(async () => {
      if (typeof navigator.storage === 'undefined' || typeof navigator.storage.getDirectory === 'undefined') return { supported: false };
      try {
        const root = await navigator.storage.getDirectory();
        const entries = [];
        for await (const [name, handle] of root.entries()) { entries.push({ name, kind: handle.kind }); }
        return { supported: true, rootEntries: entries };
      } catch { return { supported: false }; }
    });
  }

  async auditCredentialManager() {
    return this.page.evaluate(async () => {
      if (typeof navigator.credentials === 'undefined') return { supported: false };
      try {
        const creds = await navigator.credentials.get({ password: true, federated: { providers: [] } });
        return { supported: true, storedCredentials: creds ? true : false };
      } catch { return { supported: true, storedCredentials: false }; }
    });
  }

  async auditPaymentHandler() {
    return this.page.evaluate(async () => {
      if (typeof navigator.paymentHandler === 'undefined' && typeof PaymentRequest === 'undefined') return { supported: false };
      const instruments = [];
      try {
        const pr = new PaymentRequest([{ supportedMethods: 'basic-card' }], { total: { label: 'test', amount: { currency: 'USD', value: '0.01' } } });
        instruments.push({ type: 'PaymentRequest', available: true });
      } catch { instruments.push({ type: 'PaymentRequest', available: false }); }
      return { supported: true, instruments };
    });
  }

  async detectBlobURLStorage() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (code && code.includes('createObjectURL') || code.includes('blob:')) {
          results.push({ type: 'blob-url', src: s.src || 'inline', snippet: code.slice(0, 150) });
        }
      });
      return results;
    });
  }

  async detectDataURLStorage() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('img[src^="data:"], iframe[src^="data:"], object[data^="data:"]').forEach(el => {
        const src = el.src || el.data;
        if (src && src.length > 200) results.push({ tag: el.tagName, length: src.length, type: src.split(';')[0] });
      });
      return results;
    });
  }

  async auditServiceWorkerCache() {
    return this.page.evaluate(async () => {
      if (typeof caches === 'undefined') return [];
      const names = await caches.keys();
      const all = [];
      for (const name of names) {
        const cache = await caches.open(name);
        const reqs = await cache.keys();
        const entries = [];
        for (const req of reqs.slice(0, 20)) {
          const resp = await cache.match(req);
          entries.push({ url: req.url, size: resp ? (await resp.clone().text()).length : 0 });
        }
        all.push({ name, totalEntries: reqs.length, entries });
      }
      return all;
    });
  }

  async detectBeaconExfil() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (code && (code.includes('sendBeacon') || code.includes('navigator.sendBeacon') || code.includes('keepalive: true') || code.includes('fetch(') && code.includes('keepalive'))) {
          results.push({ type: 'beacon-exfil', src: s.src || 'inline', snippet: code.slice(0, 150) });
        }
      });
      return results;
    });
  }

  async detectClientSideScanning() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      const patterns = [/fingerprint/i, /fingerprintjs/i, /canvas/i, /audio/i, /fonts/i, /webgl/i, /browserleaks/i, /device/i];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        patterns.forEach(p => { if (p.test(code)) results.push({ pattern: p.source, src: s.src || 'inline' }); });
      });
      return results;
    });
  }

  async fullStorageAudit() {
    console.log('[StorageAuditor] Full deep storage audit...');
    const base = await this.fullAudit();
    const deep = {
      webSQL: await this.auditWebSQL(),
      fileSystem: await this.auditFileSystem(),
      credentialManager: await this.auditCredentialManager(),
      paymentHandler: await this.auditPaymentHandler(),
      blobURLs: await this.detectBlobURLStorage(),
      dataURLs: await this.detectDataURLStorage(),
      swCache: await this.auditServiceWorkerCache(),
      beaconExfil: await this.detectBeaconExfil(),
      clientScanning: await this.detectClientSideScanning()
    };
    return { ...base, deep };
  }
}

module.exports = { StorageAuditor };
