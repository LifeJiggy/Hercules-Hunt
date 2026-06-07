const { expect } = require('chai');
const { ClientSideScanner } = require('../index');
const { createBrowserMock } = require('../helpers/browser-mock');

describe('ClientSideScanner', function () {
  let scanner;

  beforeEach(() => {
    scanner = new ClientSideScanner({ headless: true });
  });

  describe('generateReport', () => {
    it('should return JSON report when no findings', () => {
      const report = scanner.generateReport({});
      expect(report).to.be.an('object');
      expect(report).to.have.property('summary');
    });
  });

  describe('prioritizeFindings', () => {
    it('should return empty array for no findings', () => {
      scanner.findings = [];
      expect(scanner.prioritizeFindings()).to.deep.equal([]);
    });

    it('should sort findings by severity', () => {
      scanner.findings = [
        { type: 'test', severity: 'LOW' },
        { type: 'test2', severity: 'CRITICAL' },
        { type: 'test3', severity: 'HIGH' }
      ];
      const prioritized = scanner.prioritizeFindings();
      expect(prioritized[0].severity).to.equal('CRITICAL');
      expect(prioritized[1].severity).to.equal('HIGH');
      expect(prioritized[2].severity).to.equal('LOW');
    });
  });

  describe('browser mock', () => {
    it('should create a functional jsdom mock', () => {
      const { window, document } = createBrowserMock();
      expect(document).to.exist;
      expect(window.fetch).to.be.a('function');
      expect(window.localStorage).to.exist;
      expect(window.sessionStorage).to.exist;
    });

    it('should support localStorage operations', () => {
      const { window } = createBrowserMock();
      window.localStorage.setItem('test', 'value');
      expect(window.localStorage.getItem('test')).to.equal('value');
      expect(window.localStorage.length).to.equal(1);
      window.localStorage.removeItem('test');
      expect(window.localStorage.getItem('test')).to.be.null;
    });
  });
});
