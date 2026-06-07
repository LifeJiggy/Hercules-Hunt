const { expect } = require('chai');
const { EndpointCollector } = require('../index');

describe('EndpointCollector', function () {
  let collector;

  beforeEach(() => {
    collector = new EndpointCollector();
  });

  describe('extractFromJS', () => {
    it('should find API endpoints in JS content', () => {
      const js = `
        fetch('/api/v1/users');
        axios.post('https://api.target.com/login', data);
        const url = "/api/v2/admin/users/123";
      `;
      const results = collector.extractFromJS(js);
      expect(results).to.be.an('array');
      expect(results.some(r => r.includes('/api/v1/users'))).to.be.true;
    });

    it('should return empty array for clean input', () => {
      expect(collector.extractFromJS('const x = 1;')).to.deep.equal([]);
    });
  });

  describe('extractSecrets', () => {
    it('should find hardcoded secrets in JS', () => {
      const js = 'const key = "AIzaSyA1234567890ABCDEF";';
      const results = collector.extractSecrets(js);
      expect(results).to.be.an('array');
    });

    it('should return empty for clean code', () => {
      expect(collector.extractSecrets('const x = 1;')).to.deep.equal([]);
    });
  });

  describe('exportResults', () => {
    it('should export results to a file', () => {
      const out = collector.exportResults();
      expect(out).to.be.a('string');
      expect(out).to.match(/output|endpoint|\.json/i);
    });
  });
});
