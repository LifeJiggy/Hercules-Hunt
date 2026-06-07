const { expect } = require('chai');
const { TokenAnalyzer } = require('../index');

describe('TokenAnalyzer', function () {
  let analyzer;

  beforeEach(() => {
    analyzer = new TokenAnalyzer();
  });

  describe('decodeJWT', () => {
    it('should decode a valid JWT', () => {
      const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xX1m0A';
      const result = analyzer.decodeJWT(token);
      expect(result).to.have.property('header');
      expect(result).to.have.property('payload');
      expect(result.header.alg).to.equal('HS256');
      expect(result.payload.sub).to.equal('1234567890');
    });

    it('should return invalid for bad JWT', () => {
      const result = analyzer.decodeJWT('not-a-jwt');
      expect(result).to.have.property('valid', false);
    });

    it('should handle empty string', () => {
      const result = analyzer.decodeJWT('');
      expect(result).to.have.property('valid', false);
    });
  });

  describe('testAlgNone', () => {
    it('should return alg:none test tokens', async () => {
      const result = await analyzer.testAlgNone('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature');
      expect(result).to.have.property('algNoneToken');
      expect(result).to.have.property('tests');
      expect(result.tests).to.be.an('array');
      expect(result.tests.length).to.be.at.least(2);
    });
  });

  describe('analyzeToken', () => {
    it('should return metrics for a token string', () => {
      const result = analyzer.analyzeToken('abc123XYZ');
      expect(result).to.have.property('valid');
    });
  });

  describe('fullTokenAudit', () => {
    it('should return comprehensive audit object', async () => {
      const result = await analyzer.fullTokenAudit('eyJhbGciOiJIUzI1NiJ9.payload.signature');
      expect(result).to.be.an('object');
    });
  });

  describe('base64url', () => {
    it('should convert base64url', () => {
      const result = analyzer.base64url('SGVsbG8=');
      expect(typeof result).to.equal('string');
    });
  });
});
