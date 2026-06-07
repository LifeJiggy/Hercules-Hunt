class UserFunctionalities {
  constructor(page) {
    this.page = page;
    this.sessions = new Map();
    this.activeSession = null;
  }

  async login(credentials) {
    const { url, usernameField, passwordField, submitButton, username, password, extraFields } = credentials;
    if (url) await this.page.goto(url, { waitUntil: 'networkidle' });
    await this.page.fill(usernameField, username);
    await this.page.fill(passwordField, password);
    if (extraFields) {
      for (const [selector, value] of Object.entries(extraFields)) {
        await this.page.fill(selector, value);
      }
    }
    if (submitButton) {
      await Promise.all([
        this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {}),
        this.page.click(submitButton)
      ]);
    }
    const sessionData = await this.captureSession();
    this.activeSession = `${username}@${new URL(this.page.url()).hostname}`;
    this.sessions.set(this.activeSession, sessionData);
    return sessionData;
  }

  async loginOAuth(provider, credentials) {
    const { mainUrl, oauthButton } = credentials;
    await this.page.goto(mainUrl, { waitUntil: 'networkidle' });
    const [popup] = await Promise.all([
      this.page.waitForEvent('popup', { timeout: 10000 }).catch(() => null),
      this.page.click(oauthButton)
    ]);
    if (popup) {
      if (credentials.email) await popup.fill('#identifierId', credentials.email);
      if (credentials.password) {
        await popup.fill('#password', credentials.password);
      }
      await popup.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
      await popup.close();
    }
    await this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
    return this.captureSession();
  }

  async register(registrationData) {
    const { url, fields, submitButton, expectedSuccess } = registrationData;
    await this.page.goto(url, { waitUntil: 'networkidle' });
    for (const { selector, value } of fields) {
      await this.page.fill(selector, value);
    }
    const [response] = await Promise.all([
      this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {}),
      this.page.click(submitButton)
    ]);
    const result = { success: false, message: '' };
    const currentUrl = this.page.url();
    if (expectedSuccess && currentUrl.includes(expectedSuccess)) {
      result.success = true;
      result.message = 'Registration completed';
    } else {
      const errorEl = await this.page.$('.error, .alert, [role="alert"], .message');
      if (errorEl) result.message = await errorEl.textContent();
    }
    return result;
  }

  async updateProfile(profileData) {
    const { url, fields, submitButton } = profileData;
    if (url) await this.page.goto(url, { waitUntil: 'networkidle' });
    for (const { selector, value, type } of fields) {
      if (type === 'select') {
        await this.page.selectOption(selector, value);
      } else if (type === 'upload') {
        await this.page.setInputFiles(selector, value);
      } else {
        await this.page.fill(selector, value);
      }
    }
    const [response] = await Promise.all([
      this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {}),
      this.page.click(submitButton)
    ]);
    return { success: true, url: this.page.url() };
  }

  async logout(logoutSelector = 'a[href*="logout"], button:has-text("Logout"), a[href*="signout"]') {
    await this.page.click(logoutSelector);
    await this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
    this.activeSession = null;
    return { loggedOut: true };
  }

  async switchAccount(sessionKey) {
    const session = this.sessions.get(sessionKey);
    if (!session) throw new Error(`No saved session: ${sessionKey}`);
    await this.restoreSession(session);
    this.activeSession = sessionKey;
    return true;
  }

  async saveSession(name) {
    const data = await this.captureSession();
    this.sessions.set(name, data);
    return name;
  }

  async captureSession() {
    const cookies = await this.page.context().cookies();
    const storage = await this.page.evaluate(() => ({
      localStorage: { ...localStorage },
      sessionStorage: { ...sessionStorage }
    }));
    return {
      cookies,
      storage,
      url: this.page.url(),
      userAgent: await this.page.evaluate(() => navigator.userAgent),
      timestamp: Date.now()
    };
  }

  async restoreSession(session) {
    const context = this.page.context();
    await context.addCookies(session.cookies);
    await this.page.evaluate((storage) => {
      if (storage.localStorage) {
        Object.entries(storage.localStorage).forEach(([k, v]) => localStorage.setItem(k, v));
      }
      if (storage.sessionStorage) {
        Object.entries(storage.sessionStorage).forEach(([k, v]) => sessionStorage.setItem(k, v));
      }
    }, session.storage);
    if (session.url) await this.page.goto(session.url, { waitUntil: 'networkidle' });
  }

  async exportSessions(filePath = 'output/sessions.json') {
    const dir = require('path').dirname(filePath);
    require('fs').mkdirSync(dir, { recursive: true });
    const data = {};
    for (const [name, session] of this.sessions) {
      data[name] = session;
    }
    require('fs').writeFileSync(filePath, JSON.stringify(data, null, 2));
    return filePath;
  }

  async importSessions(filePath) {
    const data = JSON.parse(require('fs').readFileSync(filePath, 'utf-8'));
    for (const [name, session] of Object.entries(data)) {
      this.sessions.set(name, session);
    }
    return Object.keys(data);
  }

  async multiAccountAction(accounts, actionFn) {
    const results = [];
    for (const account of accounts) {
      await this.switchAccount(account.sessionKey);
      const result = await actionFn(this.page, account);
      results.push({ account: account.sessionKey, result });
    }
    return results;
  }

  async fillFormAutomatically(formData) {
    const fields = await this.page.$$eval('input, textarea, select', els =>
      els.map(el => ({ name: el.name, id: el.id, type: el.type, tag: el.tagName }))
    );
    for (const field of fields) {
      const key = field.name || field.id;
      if (formData[key]) {
        const selector = field.name ? `[name="${field.name}"]` : `#${field.id}`;
        if (field.tag === 'SELECT') {
          await this.page.selectOption(selector, formData[key]);
        } else {
          await this.page.fill(selector, formData[key]);
        }
      }
    }
  }

  async bypassClientSideValidation() {
    await this.page.evaluate(() => {
      document.querySelectorAll('input').forEach(el => {
        el.removeAttribute('required');
        el.removeAttribute('pattern');
        el.removeAttribute('minlength');
        el.removeAttribute('maxlength');
        el.removeAttribute('min');
        el.removeAttribute('max');
      });
      document.querySelectorAll('form').forEach(el => {
        el.setAttribute('novalidate', '');
      });
    });
  }

  async interceptAPI(format = 'json') {
    const requests = [];
    await this.page.route('**/api/**', (route) => {
      const req = route.request();
      requests.push({
        url: req.url(),
        method: req.method(),
        headers: req.headers(),
        postData: req.postData(),
        timestamp: Date.now()
      });
      route.continue();
    });
    return {
      getAll: () => requests,
      filterByMethod: (m) => requests.filter(r => r.method === m),
      filterByUrl: (p) => requests.filter(r => r.url.includes(p)),
      export: () => format === 'json' ? JSON.stringify(requests, null, 2) : requests
    };
  }
}

module.exports = { UserFunctionalities };
