const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

class BrowserAutomation {
  constructor(options = {}) {
    this.headless = options.headless !== false;
    this.userAgent = options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
    this.timeout = options.timeout || 30000;
    this.viewport = options.viewport || { width: 1920, height: 1080 };
    this.browser = null;
    this.context = null;
    this.page = null;
    this.intercepted = [];
    this.consoleLogs = [];
  }

  async launch() {
    this.browser = await chromium.launch({
      headless: this.headless,
      args: ['--disable-blink-features=AutomationControlled']
    });
    this.context = await this.browser.newContext({
      userAgent: this.userAgent,
      viewport: this.viewport,
      ignoreHTTPSErrors: true
    });
    this.page = await this.context.newPage();
    return this;
  }

  async navigate(url) {
    await this.page.goto(url, { waitUntil: 'networkidle', timeout: this.timeout });
    return this;
  }

  async fill(selector, value) {
    await this.page.fill(selector, value);
    return this;
  }

  async click(selector) {
    await this.page.click(selector);
    return this;
  }

  async screenshot(name) {
    const dir = 'output/screenshots';
    fs.mkdirSync(dir, { recursive: true });
    await this.page.screenshot({ path: `${dir}/${name}.png`, fullPage: true });
    return `${dir}/${name}.png`;
  }

  async getText(selector) {
    return this.page.textContent(selector);
  }

  async getAttribute(selector, attr) {
    return this.page.getAttribute(selector, attr);
  }

  async extractLinks() {
    return this.page.$$eval('a', anchors => anchors.map(a => a.href).filter(Boolean));
  }

  async extractForms() {
    return this.page.$$eval('form', forms => forms.map(f => ({
      action: f.action,
      method: f.method,
      fields: Array.from(f.querySelectorAll('input, select, textarea')).map(el => ({
        name: el.name,
        type: el.type,
        value: el.value
      }))
    })));
  }

  async extractCookies() {
    return this.context.cookies();
  }

  async setCookie(cookie) {
    await this.context.addCookies([cookie]);
    return this;
  }

  async interceptRequests(filterFn) {
    await this.page.route('**', (route) => {
      const req = route.request();
      if (!filterFn || filterFn(req)) {
        this.intercepted.push({
          url: req.url(),
          method: req.method(),
          headers: req.headers(),
          postData: req.postData(),
          timestamp: Date.now()
        });
      }
      route.continue();
    });
    return this;
  }

  async captureConsole() {
    this.page.on('console', msg => {
      this.consoleLogs.push({
        type: msg.type(),
        text: msg.text(),
        timestamp: Date.now()
      });
    });
    return this;
  }

  async interceptResponses() {
    this.responses = [];
    this.page.on('response', response => {
      this.responses.push({
        url: response.url(),
        status: response.status(),
        headers: response.headers(),
        timestamp: Date.now()
      });
    });
    return this;
  }

  async takeHar(name) {
    const dir = 'output/har';
    fs.mkdirSync(dir, { recursive: true });
    await this.context.tracing.start({ screenshots: true, snapshots: true });
    await this.context.tracing.stop({ path: `${dir}/${name}.zip` });
    return `${dir}/${name}.zip`;
  }

  async evaluate(fn, ...args) {
    return this.page.evaluate(fn, ...args);
  }

  async waitForSelector(selector) {
    await this.page.waitForSelector(selector, { timeout: this.timeout });
    return this;
  }

  async waitForNavigation() {
    await this.page.waitForNavigation({ timeout: this.timeout });
    return this;
  }

  async handleDialog(accept = true) {
    this.page.on('dialog', dialog => accept ? dialog.accept() : dialog.dismiss());
    return this;
  }

  async close() {
    if (this.browser) await this.browser.close();
  }

  getIntercepted() {
    return this.intercepted;
  }

  getConsoleLogs() {
    return this.consoleLogs;
  }

  getResponses() {
    return this.responses;
  }

  async setProxy(proxyUrl) {
    if (this.browser) await this.browser.close();
    this.browser = await chromium.launch({ headless: this.headless, args: [`--proxy-server=${proxyUrl}`] });
    this.context = await this.browser.newContext({ userAgent: this.userAgent, viewport: this.viewport, ignoreHTTPSErrors: true });
    this.page = await this.context.newPage();
    return this;
  }

  async setAuthentication(credentials) {
    await this.context.setHTTPCredentials(credentials);
    return this;
  }

  async handleDownload() {
    const downloads = [];
    this.page.on('download', download => { downloads.push({ url: download.url(), path: download.path(), filename: download.suggestedFilename() }); });
    return { getDownloads: () => downloads };
  }

  async handleFileChooser() {
    return new Promise(resolve => {
      this.page.on('filechooser', fileChooser => resolve(fileChooser));
    });
  }

  async handlePopups() {
    const popups = [];
    this.page.on('popup', popup => { popups.push({ url: popup.url(), browserWindow: popup }); });
    return { getPopups: () => popups };
  }

  async setGeoLocation(lat, lng) {
    await this.context.setGeolocation({ latitude: lat, longitude: lng });
    return this;
  }

  async setPermissions(permissions) {
    await this.context.grantPermissions(permissions);
    return this;
  }

  async setDevice(deviceName) {
    const device = require('playwright').devices[deviceName];
    if (device) { this.context = await this.browser.newContext({ ...device }); this.page = await this.context.newPage(); }
    return this;
  }

  async setThrottling(downloadSpeed, uploadSpeed, latency) {
    await this.context.setOffline(false);
    await this.page.route('**', (route) => {
      const req = route.request();
      const client = this.page.context();
      setTimeout(() => route.continue(), latency || 0);
    });
    return this;
  }

  async blockResources(patterns) {
    await this.page.route('**', (route) => {
      const url = route.request().url();
      for (const p of patterns) { if (url.includes(p)) { route.abort(); return; } }
      route.continue();
    });
    return this;
  }

  async modifyResponse(urlPattern, modifyFn) {
    await this.page.route(urlPattern, async (route) => {
      const response = await route.fetch();
      const body = await response.text();
      const modified = modifyFn(body);
      route.fulfill({ response, body: modified });
    });
    return this;
  }

  async recordVideo(dir = 'output/videos') {
    const context = await this.browser.newContext({ recordVideo: { dir } });
    this.page = await context.newPage();
    this.context = context;
    return this;
  }

  async generatePDF(options = {}) {
    return this.page.pdf({ format: 'A4', ...options });
  }

  async waitForNetworkIdle(timeout = 5000) {
    await this.page.waitForLoadState('networkidle', { timeout });
    return this;
  }

  async retry(fn, retries = 3) {
    for (let i = 0; i < retries; i++) {
      try { return await fn(); } catch (e) { if (i === retries - 1) throw e; await this.sleep(1000 * (i + 1)); }
    }
  }

  async trace(name) {
    const dir = 'output/traces';
    require('fs').mkdirSync(dir, { recursive: true });
    await this.context.tracing.start({ screenshots: true, snapshots: true });
    return { stop: async () => { await this.context.tracing.stop({ path: `${dir}/${name}.zip` }); return `${dir}/${name}.zip`; } };
  }

  async accessibilitySnapshot() {
    return this.page.accessibility.snapshot();
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
}

module.exports = { BrowserAutomation };
