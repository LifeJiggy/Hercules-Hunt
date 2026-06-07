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
}

module.exports = { BrowserAutomation };
