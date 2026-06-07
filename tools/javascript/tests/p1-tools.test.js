const { expect } = require('chai');
const {
  SessionHijacker, StorageAuditor, CSRFTester,
  PrototypePollution, XSSHunter, DOMManipulation
} = require('../index');
const { createMockPage } = require('../helpers/browser-mock');

describe('StorageAuditor', function () {
  describe('detectSensitiveData', () => {
    it('should detect email patterns', async () => {
      const auditor = new StorageAuditor(createMockPage());
      const result = await auditor.detectSensitiveData({ email: 'user@example.com' }, 'localStorage');
      expect(result).to.be.an('array');
      expect(result.some(r => r.type === 'Email')).to.be.true;
    });

    it('should detect JWT patterns', async () => {
      const auditor = new StorageAuditor(createMockPage());
      const result = await auditor.detectSensitiveData(
        { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature' }, 'sessionStorage'
      );
      expect(result.some(r => r.type === 'JWT Token')).to.be.true;
    });

    it('should return empty for clean data', async () => {
      const auditor = new StorageAuditor(createMockPage());
      const result = await auditor.detectSensitiveData({ ok: 'true' }, 'test');
      expect(result).to.deep.equal([]);
    });
  });
});

describe('CSRFTester', function () {
  describe('generatePoC', () => {
    it('should generate CSRF PoC HTML', () => {
      const tester = new CSRFTester(createMockPage());
      const html = tester.generatePoC('POST', 'https://target.com/api/action', { param: 'value' });
      expect(html).to.include('<form');
      expect(html).to.include('target.com');
    });

    it('should generate GET-based PoC', () => {
      const tester = new CSRFTester(createMockPage());
      const html = tester.generatePoC('GET', 'https://target.com/api/action', { id: '1' });
      expect(html).to.include('<a href');
    });
  });
});

describe('PrototypePollution', function () {
  describe('testMergeFunctions', () => {
    it('should return merge function names', async () => {
      const pp = new PrototypePollution(createMockPage());
      const result = await pp.testMergeFunctions();
      expect(result).to.be.an('array');
      expect(result.length).to.be.at.least(3);
    });
  });
});

describe('XSSHunter', function () {
  describe('generatePolyglot', () => {
    it('should generate polyglot payloads', () => {
      const hunter = new XSSHunter(createMockPage());
      const payloads = hunter.generatePolyglot();
      expect(payloads).to.be.an('object');
      expect(payloads).to.have.property('basic');
      expect(payloads).to.have.property('htmlContext');
    });
  });
});

describe('SessionHijacker', function () {
  describe('exportFindings', () => {
    it('should not throw with empty findings', () => {
      const hijacker = new SessionHijacker(createMockPage());
      expect(() => hijacker.exportFindings()).to.not.throw();
    });
  });
});

describe('DOMManipulation', function () {
  describe('querySelector pattern helpers', () => {
    it('should provide CSS selector builder', () => {
      const dm = new DOMManipulation(createMockPage());
      expect(typeof dm.querySelector).to.equal('function');
      expect(typeof dm.querySelectorAll).to.equal('function');
    });
  });
});

describe('BrowserMock (jsdom)', function () {
  it('should support postMessage dispatching', () => {
    const { createBrowserMock } = require('../helpers/browser-mock');
    const { window } = createBrowserMock();
    let received = null;
    window.addEventListener('message', (e) => { received = e.data; });
    window.postMessage('hello', '*');
    expect(received).to.equal('hello');
  });

  it('should support fetch mock', async () => {
    const { createBrowserMock } = require('../helpers/browser-mock');
    const { window } = createBrowserMock();
    const res = await window.fetch('https://example.com');
    expect(res.ok).to.be.true;
  });

  it('should support localStorage operations', () => {
    const { createBrowserMock } = require('../helpers/browser-mock');
    const { window } = createBrowserMock();
    window.localStorage.setItem('test', 'value');
    expect(window.localStorage.getItem('test')).to.equal('value');
    expect(window.localStorage.length).to.equal(1);
  });

  it('should support cookie operations', () => {
    const { createBrowserMock } = require('../helpers/browser-mock');
    const { window } = createBrowserMock();
    window.document.cookie = 'session=abc123; path=/';
    expect(window.document.cookie).to.be.a('string');
  });
});
