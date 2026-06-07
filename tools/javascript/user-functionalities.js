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

  async testPasswordStrength() {
    const passwords = await this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('input[type="password"]').forEach(el => {
        const val = el.value || el.getAttribute('value') || '';
        results.push({
          name: el.name,
          length: val.length,
          hasUpper: /[A-Z]/.test(val),
          hasLower: /[a-z]/.test(val),
          hasDigit: /\d/.test(val),
          hasSpecial: /[^a-zA-Z0-9]/.test(val),
          minLength: el.minLength || null,
          pattern: el.pattern || null,
          autocomplete: el.autocomplete || null
        });
      });
      return results;
    });
    const findings = [];
    for (const p of passwords) {
      if (p.length < 8) findings.push({ field: p.name, issue: 'Password < 8 chars', severity: 'HIGH' });
      if (!p.hasUpper) findings.push({ field: p.name, issue: 'No uppercase letter', severity: 'MEDIUM' });
      if (!p.hasDigit) findings.push({ field: p.name, issue: 'No digit', severity: 'MEDIUM' });
      if (!p.hasSpecial) findings.push({ field: p.name, issue: 'No special char', severity: 'LOW' });
    }
    return { passwords, findings };
  }

  async testUsernameEnumeration(loginUrl, validUser, invalidUser) {
    const results = [];
    for (const { user, expect } of [{ user: validUser, expect: 'valid' }, { user: invalidUser, expect: 'invalid' }]) {
      await this.page.goto(loginUrl, { waitUntil: 'networkidle' });
      await this.page.fill('input[name="email"], input[name="username"], input[type="email"]', user);
      await this.page.fill('input[type="password"]', 'wrongpassword123!');
      await this.page.click('button[type="submit"], input[type="submit"]');
      await this.page.waitForTimeout(1000);
      const body = await this.page.evaluate(() => document.body.textContent);
      const msgMatch = body.match(/(?:error|alert|message|notification)[^.]{0,100}/i);
      results.push({ user, expected: expect, bodyMatch: msgMatch ? msgMatch[0].slice(0, 100) : 'no message', message: msgMatch ? msgMatch[0].slice(0, 200) : '' });
    }
    const msgs = results.map(r => r.bodyMatch);
    const enumDetected = msgs[0] !== msgs[1];
    if (enumDetected) this.findings.push({ type: 'username-enum', issue: 'Different error messages for valid vs invalid users', severity: 'MEDIUM' });
    return { results, enumDetected };
  }

  async testAccountLockout(loginUrl, username, attempts = 5) {
    const results = [];
    for (let i = 0; i < attempts; i++) {
      await this.page.goto(loginUrl, { waitUntil: 'networkidle' });
      await this.page.fill('input[name="email"], input[name="username"], input[type="email"]', username);
      await this.page.fill('input[type="password"]', `wrong${i}`);
      const start = Date.now();
      await this.page.click('button[type="submit"], input[type="submit"]');
      await this.page.waitForTimeout(500);
      results.push({ attempt: i + 1, elapsed: Date.now() - start });
    }
    const timingShift = results.slice(-3).every(r => r.elapsed > results[0].elapsed * 1.5);
    if (timingShift) this.findings.push({ type: 'account-lockout', issue: 'Timing shift detected — account lockout may be present', severity: 'INFO' });
    return { results, lockoutDetected: timingShift };
  }

  async testForgotPassword( forgotUrl, email ) {
    await this.page.goto(forgotUrl, { waitUntil: 'networkidle' });
    await this.page.fill('input[type="email"], input[name="email"]', email);
    await this.page.click('button[type="submit"], input[type="submit"]');
    await this.page.waitForTimeout(2000);
    const body = await this.page.evaluate(() => document.body.textContent);
    const tokenMatch = body.match(/reset[=:][a-zA-Z0-9\-_.]+/i);
    const findings = [];
    if (tokenMatch) findings.push({ issue: 'Reset token in response body', severity: 'CRITICAL', token: tokenMatch[0] });
    const responseUrl = this.page.url();
    if (responseUrl.includes('reset') || responseUrl.includes('token')) findings.push({ issue: 'Reset token in URL', severity: 'HIGH', url: responseUrl });
    if (findings.length) this.findings.push(...findings);
    return { responseUrl, findings };
  }

  async testEmailChange(emailChangeUrl, newEmail) {
    await this.page.goto(emailChangeUrl, { waitUntil: 'networkidle' });
    const fields = await this.page.$$('input[type="email"], input[name="email"]');
    const findings = [];
    for (const field of fields) {
      const name = await field.getAttribute('name') || '';
      const id = await field.getAttribute('id') || '';
      await field.fill(newEmail);
      const submitBtn = await this.page.$('button[type="submit"], input[type="submit"]');
      if (submitBtn) {
        await Promise.all([
          this.page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
          submitBtn.click()
        ]);
        const currentValues = await this.page.evaluate(() => {
          const inputs = document.querySelectorAll('input[type="email"], input[name="email"]');
          return Array.from(inputs).map(i => i.value);
        });
        if (currentValues.includes(newEmail) && !this.page.url().includes('confirm')) findings.push({ field: name || id, issue: 'Email changed without confirmation', severity: 'CRITICAL' });
      }
    }
    if (findings.length) this.findings.push(...findings);
    return findings;
  }

  async testMassAssignment(url, extraFields) {
    await this.page.goto(url, { waitUntil: 'networkidle' });
    const forms = await this.page.$$('form');
    const results = [];
    for (const form of forms) {
      const action = await form.getAttribute('action') || url;
      const method = (await form.getAttribute('method') || 'POST').toUpperCase();
      const formData = {};
      const inputs = await form.$$('input, textarea, select');
      for (const el of inputs) {
        const name = await el.getAttribute('name');
        const value = await el.getAttribute('value') || await el.inputValue();
        if (name) formData[name] = value;
      }
      for (const [key, val] of Object.entries(extraFields)) formData[key] = val;
      results.push({ action, method, formData });
    }
    if (extraFields) this.findings.push({ type: 'mass-assignment-tested', fields: Object.keys(extraFields), severity: 'INFO' });
    return results;
  }

  async testLoginCSRF(loginUrl) {
    await this.page.goto(loginUrl, { waitUntil: 'networkidle' });
    const forms = await this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('form')).map(f => ({
        action: f.action,
        hasCSRF: !!f.querySelector('input[name*="csrf"], input[name*="token"], input[name*="xsrf"], input[name="authenticity_token"]')
      }));
    });
    const noCSRF = forms.filter(f => !f.hasCSRF);
    if (noCSRF.length) this.findings.push({ type: 'login-csrf', count: noCSRF.length, issue: 'Login form missing CSRF protection', severity: 'HIGH' });
    return { forms, vulnerable: noCSRF.length > 0 };
  }

  async testSessionInURL() {
    const url = this.page.url();
    const findings = [];
    const tokenPatterns = [/[?&](?:session|token|sid|jsessionid|phpsessid|auth)=[a-zA-Z0-9\-_.%]{8,}/i, /\/[a-zA-Z0-9\-_.]{20,}\/[a-zA-Z0-9\-_.]{20,}/];
    for (const p of tokenPatterns) {
      const match = url.match(p);
      if (match) findings.push({ matched: match[0].slice(0, 50), issue: 'Session token in URL — referrer leakage risk', severity: 'HIGH' });
    }
    if (findings.length) this.findings.push(...findings);
    return { url, findings };
  }

  async testAutoLogout() {
    const startUrl = this.page.url();
    await this.page.waitForTimeout(60000);
    await this.page.goto(startUrl, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
    const stillAuthenticated = this.page.url() === startUrl;
    if (stillAuthenticated) this.findings.push({ type: 'no-auto-logout', issue: 'Session still active after 60s inactivity', severity: 'LOW' });
    return { stillAuthenticated };
  }

  async testConcurrentSessionLimit(loginUrl, credentials) {
    const results = [];
    for (let i = 0; i < 3; i++) {
      const ctx = await this.page.context().browser().newContext();
      const p = await ctx.newPage();
      await p.goto(loginUrl, { waitUntil: 'networkidle' });
      await p.fill(credentials.usernameField, credentials.username);
      await p.fill(credentials.passwordField, credentials.password);
      await p.click(credentials.submitButton);
      await p.waitForTimeout(2000);
      const loggedIn = p.url() !== loginUrl;
      await ctx.close();
      results.push({ session: i + 1, loggedIn });
    }
    const allLoggedIn = results.every(r => r.loggedIn);
    if (allLoggedIn) this.findings.push({ type: 'no-concurrent-limit', issue: 'No limit on concurrent sessions', severity: 'MEDIUM' });
    return { results, unlimited: allLoggedIn };
  }
}

module.exports = { UserFunctionalities };
