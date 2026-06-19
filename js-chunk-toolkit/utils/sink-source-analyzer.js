const fs = require('fs');
const path = require('path');

const CONFIG_PATH = path.join(__dirname, '..', 'config', 'sink-source-map.json');
let config = null;

function loadConfig() {
  if (!config) {
    try { config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8')); }
    catch (e) { config = { sources: {}, sinks: {}, chains: [] }; }
  }
  return config;
}

function navigateProperty(obj, pathStr) {
  const parts = pathStr.split('.');
  let current = obj;
  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) current = current[part];
    else return undefined;
  }
  return current;
}

function extractSinkAccessPatterns(code) {
  const config = loadConfig();
  const results = [];

  const sinkPatterns = {
    'innerHTML': /\.innerHTML\s*=/g,
    'outerHTML': /\.outerHTML\s*=/g,
    'document.write': /document\.write\s*\(/g,
    'eval': /\beval\s*\(/g,
    'Function': /new\s+Function\s*\(/g,
    'setTimeout.string': /setTimeout\s*\(\s*['"`]/g,
    'setInterval.string': /setInterval\s*\(\s*['"`]/g,
    'dangerouslySetInnerHTML': /dangerouslySetInnerHTML\s*=/g,
    'location.href': /location\.href\s*=/g,
    'location.assign': /location\.assign\s*\(/g,
    'location.replace': /location\.replace\s*\(/g,
    'insertAdjacentHTML': /\.insertAdjacentHTML\s*\(/g,
    'postMessage': /\.postMessage\s*\(/g,
    'localStorage.setItem': /localStorage\.setItem\s*\(/g,
  };

  const sourcePatterns = {
    'window.location.hash': /location\.hash/g,
    'window.location.search': /location\.search/g,
    'document.URL': /document\.URL/g,
    'document.referrer': /document\.referrer/g,
    'document.cookie': /document\.cookie/g,
    'localStorage.getItem': /localStorage\.getItem\s*\(/g,
    'postMessage': /addEventListener\s*\(\s*['"]message['"]/g,
    'input.value': /\.value\s*[)=]/g,
  };

  for (const [name, re] of Object.entries(sinkPatterns)) {
    let m;
    while ((m = re.exec(code)) !== null) {
      const line = code.substring(0, m.index).split('\n').length;
      const ctx = code.substring(Math.max(0, m.index - 80), m.index + 80);
      results.push({
        type: 'sink', name, line, index: m.index,
        severity: (config.sinks[name] || {}).severity || 'MEDIUM',
        cvss: (config.sinks[name] || {}).cvss || 5.0,
        exploit: (config.sinks[name] || {}).exploit || 'Unknown',
        context: ctx.substring(0, 160),
        nearSources: []
      });
    }
  }

  for (const result of results) {
    const ctxBefore = code.substring(Math.max(0, result.index - 400), result.index);
    for (const [name, re] of Object.entries(sourcePatterns)) {
      if (re.test(ctxBefore)) {
        result.nearSources.push(name);
        re.lastIndex = 0;
      }
    }
    result.sourceCount = result.nearSources.length;
    const chainKey = result.nearSources.find(s => config.chains.some(c => c.from.includes(s) && c.to === result.name));
    if (chainKey) {
      const chain = config.chains.find(c => c.from.includes(chainKey) && c.to === result.name);
      if (chain) {
        result.chainVuln = chain.vuln;
        result.chainSeverity = chain.severity;
      }
    }
  }

  results.sort((a, b) => b.sourceCount - a.sourceCount || (severityRank(b.severity) - severityRank(a.severity)));
  return results;
}

function severityRank(s) {
  const ranks = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  return ranks[s] || 0;
}

function analyzeSinkSources(code) {
  const findings = extractSinkAccessPatterns(code);
  return {
    totalSinks: findings.length,
    sourcesFound: [...new Set(findings.flatMap(f => f.nearSources))],
    bySeverity: {
      CRITICAL: findings.filter(f => (f.chainSeverity || f.severity) === 'CRITICAL').length,
      HIGH: findings.filter(f => (f.chainSeverity || f.severity) === 'HIGH').length,
      MEDIUM: findings.filter(f => (f.chainSeverity || f.severity) === 'MEDIUM').length,
    },
    chainedFindings: findings.filter(f => f.chainVuln).length,
    findings: findings.slice(0, 50)
  };
}

module.exports = { loadConfig, extractSinkAccessPatterns, analyzeSinkSources };
