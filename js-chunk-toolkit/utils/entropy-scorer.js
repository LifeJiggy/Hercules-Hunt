const path = require('path');
const harden = require(path.join(__dirname, 'harden-base.js'));

const ENTROPY_THRESHOLDS = {
  HIGH: 4.5,
  SUSPICIOUS: 3.5,
  MEDIUM: 2.5
};

function shannonEntropy(str) {
  if (!str || str.length < 8) return 0;
  const freq = {};
  for (const ch of str) { freq[ch] = (freq[ch] || 0) + 1; }
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

function scoreEntropy(str) {
  const e = shannonEntropy(str);
  if (e >= ENTROPY_THRESHOLDS.HIGH) return { entropy: e, level: 'HIGH', reason: 'High entropy — likely secret or encoded payload' };
  if (e >= ENTROPY_THRESHOLDS.SUSPICIOUS) return { entropy: e, level: 'SUSPICIOUS', reason: 'Suspicious entropy — check manually' };
  if (e >= ENTROPY_THRESHOLDS.MEDIUM) return { entropy: e, level: 'MEDIUM', reason: 'Moderate entropy — possible encoding' };
  return { entropy: e, level: 'LOW', reason: 'Low entropy — likely natural language or code' };
}

function extractHighEntropyStrings(content, minLen = 20, maxLen = 5000) {
  const seen = new Set();
  const results = [];

  const patterns = [
    /[A-Za-z0-9+/]{40,}(?:[A-Za-z0-9+/]{4})*(?:[AQgw]==|[AEIMQUYcgkosw048]=)?/g,
    /[a-f0-9]{32,}/gi,
    /gh[pousr]_[A-Za-z0-9]{24,}/g,
    /AKIA[0-9A-Z]{16}/g,
    /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    /sk-[A-Za-z0-9]{32,}/g,
    /xox[baprs]-[A-Za-z0-9]{10,}/g,
    /[A-Za-z0-9_-]{40,}/g,
  ];

  const urlRe = /https?:\/\/[^\s"'`)]+/g;

  for (const re of patterns) {
    let m;
    while ((m = re.exec(content)) !== null) {
      const str = m[0];
      if (str.length < minLen || str.length > maxLen) continue;
      if (seen.has(str)) continue;
      seen.add(str);
      if (urlRe.test(str)) { urlRe.lastIndex = 0; continue; }
      urlRe.lastIndex = 0;
      const scored = scoreEntropy(str);
      if (scored.level !== 'LOW') {
        results.push({
          value: str.substring(0, 150),
          length: str.length,
          entropy: scored.entropy,
          level: scored.level,
          reason: scored.reason,
          index: m.index,
          line: content.substring(0, m.index).split('\n').length
        });
      }
    }
  }

  results.sort((a, b) => b.entropy - a.entropy);
  return results;
}

function scanSecretsByEntropy(content) {
  const results = extractHighEntropyStrings(content);
  return {
    total: results.length,
    byLevel: {
      HIGH: results.filter(r => r.level === 'HIGH').length,
      SUSPICIOUS: results.filter(r => r.level === 'SUSPICIOUS').length,
      MEDIUM: results.filter(r => r.level === 'MEDIUM').length,
    },
    topHigh: results.filter(r => r.level === 'HIGH').slice(0, 20),
    topSuspicious: results.filter(r => r.level === 'SUSPICIOUS').slice(0, 10),
  };
}

module.exports = { shannonEntropy, scoreEntropy, extractHighEntropyStrings, scanSecretsByEntropy, ENTROPY_THRESHOLDS };
