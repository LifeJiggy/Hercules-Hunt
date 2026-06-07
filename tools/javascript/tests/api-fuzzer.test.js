const { expect } = require('chai');
const { APIFuzzer } = require('../index');

describe('APIFuzzer', function () {
  let fuzzer;

  beforeEach(() => {
    fuzzer = new APIFuzzer();
    fuzzer.send = async () => ({ status: 200, body: '', bodyLength: 0, headers: { 'content-type': 'text/plain' } });
    fuzzer.sleep = async () => {};
  });

  describe('fuzzMethod', () => {
    it('should return HTTP method fuzz results', async () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE'];
      const result = await fuzzer.fuzzMethod('https://example.com/api/test', 'GET', methods);
      expect(result).to.be.an('array');
      expect(result.length).to.be.at.least(1);
    });
  });

  describe('fuzzHeaders', () => {
    it('should return header fuzz results', async () => {
      const result = await fuzzer.fuzzHeaders('https://example.com/api/test');
      expect(result).to.be.an('array');
    });
  });

  describe('fuzzParameters', () => {
    it('should fuzz given parameters', async () => {
      const result = await fuzzer.fuzzParameters('https://example.com/api', 'id', ['1', '2', '3']);
      expect(result).to.be.an('array');
      expect(result.length).to.equal(3);
    });
  });

  describe('fuzzContentTypes', () => {
    it('should fuzz content types', async () => {
      const result = await fuzzer.fuzzContentTypes('https://example.com/api');
      expect(result).to.be.an('array');
    });
  });

  describe('compareResponses', () => {
    it('should detect anomalous responses', () => {
      const baseline = { status: 200, bodyLength: 100, elapsed: 100 };
      const responses = [
        { status: 200, bodyLength: 100, elapsed: 90 },
        { status: 403, bodyLength: 50, elapsed: 200 }
      ];
      const result = fuzzer.compareResponses(baseline, responses);
      expect(result).to.be.an('array');
      expect(result.length).to.equal(1);
    });
  });

  describe('detectWebSocket', () => {
    it('should handle missing WebSocket gracefully', async () => {
      const result = await fuzzer.detectWebSocket('https://example.com');
      expect(result).to.have.property('supported');
    });
  });

  describe('fullAPIScan', () => {
    it('should return full scan results object', async () => {
      const result = await fuzzer.fullAPIScan('https://example.com/api/test');
      expect(result).to.be.an('object');
    });
  });
});
