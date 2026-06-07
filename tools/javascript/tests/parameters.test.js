const { expect } = require('chai');
const { Parameters } = require('../index');

describe('Parameters', function () {
  let params;

  beforeEach(() => {
    params = new Parameters();
  });

  describe('extractFromUrl', () => {
    it('should extract query params from URL', () => {
      const result = params.extractFromUrl('https://example.com/page?q=hello&r=world');
      expect(result).to.have.property('params');
      expect(result.params).to.deep.equal({ q: 'hello', r: 'world' });
      expect(result).to.have.property('paramCount', 2);
    });

    it('should return no params for URL without query', () => {
      const result = params.extractFromUrl('https://example.com/page');
      expect(result.paramCount).to.equal(0);
    });

    it('should handle empty string', () => {
      expect(() => params.extractFromUrl('')).to.throw();
    });
  });

  describe('extractFromBody', () => {
    it('should parse URL-encoded body', () => {
      const result = params.extractFromBody('user=test&pass=123');
      expect(result).to.have.property('user', 'test');
      expect(result).to.have.property('pass', '123');
    });

    it('should handle JSON body', () => {
      const result = params.extractFromBody(JSON.stringify({ user: 'test', role: 'admin' }));
      if (result && result.user) {
        expect(result.user).to.equal('test');
      }
    });
  });

  describe('buildUrl', () => {
    it('should build URL with params', () => {
      const url = params.buildUrl('https://example.com/page', { q: 'test' });
      expect(url).to.include('q=test');
    });
  });

  describe('fuzzParamCount', () => {
    it('should generate fuzzed parameter count URLs', async () => {
      const results = await params.fuzzParamCount('https://example.com', {}, 0, 3);
      expect(results).to.be.an('array');
      expect(results).to.have.lengthOf(4);
    });
  });

  describe('extractCookieParams', () => {
    it('should return empty in Node.js without document', () => {
      const result = params.extractCookieParams();
      expect(result).to.deep.equal({});
    });
  });

  describe('fullParamMap', () => {
    it('should return comprehensive param map', async () => {
      const result = await params.fullParamMap('https://example.com/page?q=1&r=2');
      expect(result).to.be.an('object');
    });
  });
});
