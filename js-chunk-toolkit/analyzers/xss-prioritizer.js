const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));
const args = process.argv.slice(2);

const TARGET_PATTERNS = [
  { name: 'innerHTML assignment', re: /\.innerHTML\s*=/g, base: 8.0, sinkType: 'direct', note: 'Direct DOM write — classic XSS' },
  { name: 'outerHTML assignment', re: /\.outerHTML\s*=/g, base: 8.0, sinkType: 'direct', note: 'Replaces entire element' },
  { name: 'document.write()', re: /document\.write\s*\(/g, base: 7.5, sinkType: 'direct', note: 'Overwrites document if called after load' },
  { name: 'dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML\s*=/g, base: 8.0, sinkType: 'react', note: 'React XSS — bypasses JSX escaping' },
  { name: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/g, base: 7.5, sinkType: 'direct', note: 'Parses HTML string directly' },
  { name: 'eval(string)', re: /\beval\s*\([^)]*['"`]/g, base: 9.0, sinkType: 'eval', note: 'String-based eval = immediate RCE' },
  { name: 'setTimeout(string)', re: /setTimeout\s*\(\s*['"`][^)]{20,}['"`]/g, base: 7.5, sinkType: 'eval', note: 'String setTimeout is eval by another name' },
  { name: 'setInterval(string)', re: /setInterval\s*\(\s*['"`][^)]{20,}['"`]/g, base: 7.5, sinkType: 'eval', note: 'String setInterval = periodic eval' },
  { name: 'Function(string)', re: /new\s+Function\s*\([^)]*['"`]/g, base: 8.5, sinkType: 'eval', note: 'Function constructor = eval with scope' },
  { name: 'location.href assignment', re: /location\.href\s*=/g, base: 7.0, sinkType: 'redirect', note: 'Open redirect + XSS via javascript: URL' },
  { name: 'location.assign()', re: /location\.assign\s*\(/g, base: 7.0, sinkType: 'redirect', note: 'Programmatic navigation' },
  { name: 'location.replace()', re: /location\.replace\s*\(/g, base: 7.0, sinkType: 'redirect', note: 'Replaces current history entry' },
  { name: 'open() with user input', re: /\.open\s*\([^)]+/g, base: 6.5, sinkType: 'redirect', note: 'window.open(target, ...)' },
  { name: 'postMessage()', re: /\.postMessage\s*\(/g, base: 6.5, sinkType: 'message', note: 'Cross-origin message sending' },
  { name: 'addEventListener(message)', re: /addEventListener\s*\(\s*['"]message['"]/g, base: 7.0, sinkType: 'message', note: 'postMessage receiver — check origin validation' },
  { name: 'script.src assignment', re: /\.src\s*=\s*['"`]https?:\/\/[^'"]+/g, base: 7.5, sinkType: 'script', note: 'Dynamic script injection' },
  { name: 'createElement(script)', re: /createElement\s*\(\s*['"]script['"]\s*\)/g, base: 7.5, sinkType: 'script', note: 'Script element creation' },
  { name: 'srcdoc assignment', re: /\.srcdoc\s*=/g, base: 8.0, sinkType: 'iframe', note: 'iframe srcdoc = innerHTML in iframe' },
  { name: 'setAttribute(on*)', re: /\.setAttribute\s*\(\s*['"]on/g, base: 7.0, sinkType: 'dom', note: 'Inline event handler via setAttribute' },
  { name: 'createContextualFragment', re: /createContextualFragment\s*\(/g, base: 7.5, sinkType: 'dom', note: 'Range.createContextualFragment = innerHTML' },
  { name: 'style.cssText assignment', re: /\.cssText\s*=/g, base: 5.0, sinkType: 'style', note: 'CSS injection — potential exfil' },
  { name: 'outerText assignment', re: /\.outerText\s*=/g, base: 5.0, sinkType: 'dom', note: 'Less common but parsers vary' },
];

const PROXIMITY_SOURCES = [
  { name: 'location.hash', re: /location\.hash/g, weight: 1.5 },
  { name: 'location.search', re: /location\.search/g, weight: 1.5 },
  { name: 'location.href read', re: /\blocation\.href\b(?!\s*=)/g, weight: 1.3 },
  { name: 'document.URL', re: /document\.URL\b/g, weight: 1.4 },
  { name: 'document.referrer', re: /document\.referrer/g, weight: 1.2 },
  { name: 'document.cookie', re: /document\.cookie\b/g, weight: 1.1 },
  { name: 'postMessage event', re: /\.data\b/g, weight: 1.4 },
  { name: 'localStorage.getItem', re: /localStorage\.getItem\s*\(/g, weight: 1.0 },
  { name: 'sessionStorage.getItem', re: /sessionStorage\.getItem\s*\(/g, weight: 1.0 },
  { name: 'URL parameter', re: /new\s+URL(?:Search)?Params\s*\(/g, weight: 1.3 },
  { name: 'input.value', re: /\.value\b/g, weight: 1.2 },
  { name: 'innerText read', re: /\.innerText\b(?!\s*=)/g, weight: 0.8 },
  { name: 'textContent read', re: /\.textContent\b(?!\s*=)/g, weight: 0.8 },
  { name: 'fetch response', re: /\.text\s*\(|\.json\s*\(/g, weight: 1.1 },
  { name: 'WebSocket message', re: /onmessage\s*=|addEventListener\s*\(\s*['"]message['"]/g, weight: 1.3 },
  { name: 'history.state', re: /history\.state/g, weight: 0.9 },
  { name: 'window.name', re: /\bwindow\.name\b/g, weight: 1.0 },
];

function findNearSources(code, index, radius = 300) {
  const sources = [];
  const contextBefore = code.substring(Math.max(0, index - radius), index);
  const contextAfter = code.substring(index, Math.min(code.length, index + radius));
  const context = contextBefore + contextAfter;
  for (const src of PROXIMITY_SOURCES) {
    src.re.lastIndex = 0;
    if (src.re.test(context)) {
      sources.push(src.name);
      src.re.lastIndex = 0;
    }
  }
  return sources;
}

function prioritizeXSS(code) {
  const findings = [];

  for (const target of TARGET_PATTERNS) {
    target.re.lastIndex = 0;
    let m;
    while ((m = target.re.exec(code)) !== null) {
      const line = code.substring(0, m.index).split('\n').length;
      const sources = findNearSources(code, m.index);

      let exploitability = target.base;
      if (sources.length > 0) {
        const maxWeight = Math.max(...sources.map(s => (PROXIMITY_SOURCES.find(p => p.name === s) || {}).weight || 1));
        exploitability = Math.min(10, exploitability * maxWeight);
      }

      const nearCode = code.substring(Math.max(0, m.index - 80), Math.min(code.length, m.index + 60));

      findings.push({
        sink: target.name,
        line,
        baseCvss: target.base,
        exploitability: Math.round(exploitability * 10) / 10,
        sinkType: target.sinkType,
        sources: sources.length > 0 ? sources : ['no_source_detected'],
        sourceCount: sources.length,
        severity: exploitability >= 8 ? 'CRITICAL' : exploitability >= 6 ? 'HIGH' : exploitability >= 4 ? 'MEDIUM' : 'LOW',
        note: target.note,
        context: nearCode.substring(0, 120),
      });
    }
  }

  findings.sort((a, b) => b.exploitability - a.exploitability || b.sourceCount - a.sourceCount);
  return findings;
}

function generateReport(code, inputFile) {
  const findings = prioritizeXSS(code);
  const filename = path.basename(inputFile);

  console.log(`\n========================================`);
  console.log(`  XSS Sink Prioritization Report`);
  console.log(`========================================`);
  console.log(`  File: ${filename}`);
  console.log(`  Total sinks found: ${findings.length}`);
  console.log('');

  if (findings.length === 0) {
    console.log('  No XSS sinks detected.\n');
    return { findings, total: 0, critical: 0, high: 0 };
  }

  const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) bySeverity[f.severity]++;

  const byType = {};
  for (const f of findings) { byType[f.sinkType] = (byType[f.sinkType] || 0) + 1; }

  console.log('  By severity:');
  Object.entries(bySeverity).filter(([, c]) => c > 0).forEach(([sev, count]) => {
    console.log(`    ${harden.colorize(sev)}: ${count}`);
  });
  console.log('');
  console.log('  By sink type:');
  Object.entries(byType).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
    console.log(`    ${type.padEnd(12)}: ${count}`);
  });
  console.log('');

  const withSources = findings.filter(f => f.sourceCount > 0);
  if (withSources.length > 0) {
    console.log(`  Sinks with nearby sources (chained):`);
    withSources.slice(0, 15).forEach((f, i) => {
      const s = f.sources.slice(0, 3).join(', ');
      console.log(`    ${(i + 1).toString().padStart(2)}. ${f.sink.padEnd(32)} CVSS:${f.exploitability.toFixed(1)} line ${f.line} (src: ${s})`);
    });
    console.log('');
  }

  console.log('  Top prioritized findings:');
  findings.slice(0, 10).forEach((f, i) => {
    console.log(`    ${(i + 1).toString().padStart(2)}. [${harden.colorize(f.severity)}] ${f.sink.padEnd(32)} CVSS:${f.exploitability.toFixed(1)} Ln:${f.line}`);
    if (f.sourceCount > 0) console.log(`        Near sources: ${f.sources.slice(0, 3).join(', ')}`);
  });
  console.log('');

  return { findings, total: findings.length, ...bySeverity };
}

if (require.main === module) {
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  generateReport(loaded.content, args[0]);
}

module.exports = { prioritizeXSS, generateReport, TARGET_PATTERNS, PROXIMITY_SOURCES };
