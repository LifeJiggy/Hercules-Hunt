const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node taint-analyzer.js <file.js>'); process.exit(1); }

const loaded = harden.safeLoadFile(args[0]);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
const code = loaded.content;

const SOURCES = [
  { name: 'location.hash', re: /location\.hash/g, taint: 'url_fragment', weight: 10 },
  { name: 'location.search', re: /location\.search/g, taint: 'url_param', weight: 10 },
  { name: 'location.href', re: /\blocation\.href\b(?!\s*=)/g, taint: 'url_full', weight: 9 },
  { name: 'document.URL', re: /document\.URL\b/g, taint: 'url_full', weight: 9 },
  { name: 'document.documentURI', re: /document\.documentURI/g, taint: 'url_full', weight: 9 },
  { name: 'document.referrer', re: /document\.referrer/g, taint: 'url_full', weight: 8 },
  { name: 'document.cookie', re: /document\.cookie\b(?!\s*=)/g, taint: 'cookie', weight: 8 },
  { name: 'postMessage event.data', re: /\.data\b/g, taint: 'message', weight: 7 },
  { name: 'localStorage.getItem', re: /localStorage\.getItem\s*\(/g, taint: 'storage', weight: 8 },
  { name: 'sessionStorage.getItem', re: /sessionStorage\.getItem\s*\(/g, taint: 'storage', weight: 7 },
  { name: 'URLSearchParams.get', re: /\.get\s*\(/g, taint: 'url_param', weight: 6 },
  { name: 'new URL().searchParams', re: /new\s+URL\s*\(/g, taint: 'url_param', weight: 7 },
  { name: 'history.state', re: /history\.state/g, taint: 'state', weight: 5 },
  { name: 'window.name', re: /\bwindow\.name\b/g, taint: 'state', weight: 6 },
  { name: 'input.value', re: /\.value\b(?!\s*=)/g, taint: 'user_input', weight: 5 },
  { name: 'WebSocket message', re: /onmessage\s*=/g, taint: 'message', weight: 7 },
  { name: 'fetch() response', re: /\.then\s*\(\s*(?:function|\([^)]*\))/g, taint: 'server_response', weight: 6 },
  { name: 'XMLHttpRequest response', re: /\.responseText\b|\.response\b(?!\s*=)/g, taint: 'server_response', weight: 6 },
];

const SINKS = [
  { name: 'innerHTML =', re: /\.innerHTML\s*=/g, vuln: 'XSS', severity: 'CRITICAL', weight: 10 },
  { name: 'outerHTML =', re: /\.outerHTML\s*=/g, vuln: 'XSS', severity: 'CRITICAL', weight: 10 },
  { name: 'document.write()', re: /document\.write\s*\(/g, vuln: 'XSS', severity: 'CRITICAL', weight: 9 },
  { name: 'eval()', re: /\beval\s*\(/g, vuln: 'RCE', severity: 'CRITICAL', weight: 10 },
  { name: 'Function()', re: /new\s+Function\s*\(/g, vuln: 'RCE', severity: 'CRITICAL', weight: 9 },
  { name: 'setTimeout(string)', re: /setTimeout\s*\(\s*['"`][^)]{20,}/g, vuln: 'RCE', severity: 'HIGH', weight: 8 },
  { name: 'dangerouslySetInnerHTML', re: /dangerouslySetInnerHTML\s*=/g, vuln: 'XSS', severity: 'CRITICAL', weight: 10 },
  { name: 'fetch() URL', re: /fetch\s*\(/g, vuln: 'SSRF', severity: 'HIGH', weight: 8 },
  { name: 'location.href =', re: /location\.href\s*=/g, vuln: 'Open Redirect', severity: 'HIGH', weight: 7 },
  { name: 'open()', re: /\.open\s*\(/g, vuln: 'Open Redirect', severity: 'MEDIUM', weight: 6 },
  { name: 'import()', re: /import\s*\(/g, vuln: 'RCE', severity: 'HIGH', weight: 7 },
  { name: 'exec()', re: /\bexec\s*\(/g, vuln: 'Command Injection', severity: 'CRITICAL', weight: 10 },
  { name: 'eval() on stored', re: /\.innerHTML\s*=\s*localStorage|\.innerHTML\s*=\s*sessionStorage/g, vuln: 'Stored XSS', severity: 'CRITICAL', weight: 10 },
];

const INDIRECT_INJECTION_PATTERNS = [
  { pattern: 'localStorage → innerHTML', re: /localStorage\.getItem[\s\S]{0,200}innerHTML\s*=/g, severity: 'CRITICAL', chain: 'Stored XSS via localStorage' },
  { pattern: 'localStorage → eval', re: /localStorage\.getItem[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'Stored RCE via localStorage' },
  { pattern: 'localStorage → fetch URL', re: /localStorage\.getItem[\s\S]{0,200}fetch\s*\(/g, severity: 'HIGH', chain: 'Stored SSRF via localStorage' },
  { pattern: 'cookie → innerHTML', re: /document\.cookie[\s\S]{0,200}innerHTML\s*=/g, severity: 'CRITICAL', chain: 'Cookie injection XSS' },
  { pattern: 'cookie → eval', re: /document\.cookie[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'Cookie injection RCE' },
  { pattern: 'cookie → fetch URL', re: /document\.cookie[\s\S]{0,200}fetch\s*\(/g, severity: 'HIGH', chain: 'Cookie → SSRF' },
  { pattern: 'hash → innerHTML', re: /location\.hash[\s\S]{0,200}innerHTML\s*=/g, severity: 'CRITICAL', chain: 'Reflected DOM XSS via hash' },
  { pattern: 'hash → eval', re: /location\.hash[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'DOM RCE via hash' },
  { pattern: 'hash → fetch URL', re: /location\.hash[\s\S]{0,200}fetch\s*\(/g, severity: 'HIGH', chain: 'Hash → SSRF' },
  { pattern: 'search → innerHTML', re: /location\.search[\s\S]{0,200}innerHTML\s*=/g, severity: 'CRITICAL', chain: 'Reflected DOM XSS via query' },
  { pattern: 'search → eval', re: /location\.search[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'DOM RCE via query param' },
  { pattern: 'postMessage → innerHTML', re: /\.data[\s\S]{0,200}innerHTML\s*=/g, severity: 'CRITICAL', chain: 'postMessage XSS' },
  { pattern: 'postMessage → eval', re: /\.data[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'postMessage RCE' },
  { pattern: 'postMessage → fetch URL', re: /\.data[\s\S]{0,200}fetch\s*\(/g, severity: 'HIGH', chain: 'postMessage SSRF' },
  { pattern: 'stored → second-order eval', re: /innerHTML[\s\S]{0,200}(?:eval|Function)\s*\(/g, severity: 'CRITICAL', chain: 'Second-order injection via HTML parse → eval' },
];

const indirectFindings = [];
for (const ip of INDIRECT_INJECTION_PATTERNS) {
  ip.re.lastIndex = 0;
  let m;
  while ((m = ip.re.exec(code)) !== null) {
    const line = code.substring(0, m.index).split('\n').length;
    const ctx = code.substring(Math.max(0, m.index - 30), Math.min(code.length, m.index + m[0].length + 30)).replace(/\n/g, ' ').substring(0, 150);
    indirectFindings.push({ pattern: ip.pattern, line, severity: ip.severity, chain: ip.chain, context: ctx });
  }
}

const sourcePositions = [];
for (const src of SOURCES) {
  src.re.lastIndex = 0;
  let m;
  while ((m = src.re.exec(code)) !== null) {
    sourcePositions.push({ name: src.name, index: m.index, taint: src.taint, weight: src.weight, line: code.substring(0, m.index).split('\n').length });
  }
}

const sinkPositions = [];
for (const sink of SINKS) {
  sink.re.lastIndex = 0;
  let m;
  while ((m = sink.re.exec(code)) !== null) {
    sinkPositions.push({ name: sink.name, index: m.index, vuln: sink.vuln, severity: sink.severity, weight: sink.weight, line: code.substring(0, m.index).split('\n').length });
  }
}

const taintChains = [];
for (const sink of sinkPositions) {
  const nearbySources = sourcePositions
    .filter(s => s.index < sink.index && s.index > sink.index - 500 && sink.index - s.index < 500)
    .sort((a, b) => (sink.index - a.index) - (sink.index - b.index));
  if (nearbySources.length > 0) {
    const maxWeight = Math.max(...nearbySources.map(s => s.weight));
    const adjustedSeverity = sink.weight + maxWeight > 16 ? 'CRITICAL' : sink.weight + maxWeight > 12 ? 'HIGH' : sink.severity;
    taintChains.push({
      sink: sink.name, source: nearbySources[0].name, sinkLine: sink.line, sourceLine: nearbySources[0].line,
      vuln: sink.vuln, severity: adjustedSeverity, distance: sink.index - nearbySources[0].index,
      sourceTaint: nearbySources[0].taint
    });
  }
}

function generateTaintGraph() {
  const graph = [];
  for (const chain of taintChains) {
    graph.push(`  "${chain.source}" → "${chain.sink}" [label="${chain.vuln} (${chain.severity})" color="${chain.severity === 'CRITICAL' ? 'red' : 'orange'}"]`);
  }
  return graph;
}

console.log(`\n========================================`);
console.log(`  Taint Analysis + Indirect Injection`);
console.log(`========================================`);
console.log(`  Sources found:          ${sourcePositions.length}`);
console.log(`  Sinks found:            ${sinkPositions.length}`);
console.log(`  Taint chains:           ${taintChains.length}`);
console.log(`  Indirect injections:    ${indirectFindings.length}`);
console.log('');

if (taintChains.length > 0) {
  console.log('  Source → Sink taint chains:');
  const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [] };
  for (const chain of taintChains) {
    if (bySeverity[chain.severity]) bySeverity[chain.severity].push(chain);
  }
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM']) {
    const items = bySeverity[sev];
    if (!items || items.length === 0) continue;
    console.log(`    ${harden.colorize(sev)} (${items.length}):`);
    items.slice(0, 8).forEach(c => {
      console.log(`      ${c.source} → ${c.sink}  (${c.vuln}, dist: ${c.distance}ch)`);
    });
  }
  console.log('');

  const taintGraph = generateTaintGraph();
  if (taintGraph.length > 0) {
    console.log('  Taint flow (DOT format):');
    console.log('  digraph TaintFlow {');
    taintGraph.slice(0, 15).forEach(l => console.log(l));
    console.log('  }');
    console.log('');
  }
}

if (indirectFindings.length > 0) {
  console.log('  Indirect injection paths (stored → second-order):');
  const bySev = {};
  for (const f of indirectFindings) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
  Object.entries(bySev).forEach(([s, c]) => console.log(`    ${harden.colorize(s)}: ${c}`));
  console.log('');
  indirectFindings.slice(0, 10).forEach(f => {
    console.log(`    [${harden.colorize(f.severity)}] ${f.pattern} Ln ${f.line}`);
    console.log(`      Chain: ${f.chain}`);
    console.log(`      Context: ${f.context.substring(0, 100)}`);
  });
  console.log('');
}

if (sourcePositions.length === 0 && sinkPositions.length === 0 && indirectFindings.length === 0) {
  console.log('  No taint sources, sinks, or indirect injection patterns detected.\n');
}

module.exports = { SOURCES, SINKS, INDIRECT_INJECTION_PATTERNS };
