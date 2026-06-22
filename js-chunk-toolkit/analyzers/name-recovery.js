const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node name-recovery.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

const NGRAM_MAP = {
  a: ['args', 'accumulator', 'acc', 'async'],
  b: ['body', 'buffer', 'base', 'bundle'],
  c: ['config', 'context', 'cache', 'client', 'callback', 'collection'],
  d: ['data', 'document', 'done', 'delay', 'destination'],
  e: ['error', 'event', 'element', 'entry', 'exports'],
  f: ['function', 'file', 'field', 'filter', 'flag', 'fn'],
  g: ['global', 'group', 'guard', 'generator'],
  h: ['handler', 'header', 'hash', 'host', 'history'],
  i: ['input', 'index', 'item', 'id', 'instance'],
  j: ['json', 'job', 'join', 'jwt'],
  k: ['key', 'keys', 'known'],
  l: ['list', 'length', 'label', 'line', 'local', 'loader'],
  m: ['module', 'map', 'method', 'message', 'model', 'match'],
  n: ['name', 'node', 'next', 'number', 'namespace'],
  o: ['output', 'option', 'object', 'offset', 'origin'],
  p: ['path', 'param', 'plugin', 'props', 'payload', 'process'],
  q: ['query', 'queue', 'quota'],
  r: ['result', 'response', 'request', 'route', 'resolve', 'ref'],
  s: ['source', 'state', 'string', 'selector', 'size', 'stack', 'status'],
  t: ['target', 'type', 'test', 'token', 'timeout', 'temporary', 'total'],
  u: ['url', 'update', 'utils', 'user', 'unique'],
  v: ['value', 'validator', 'version', 'variable'],
  w: ['worker', 'warning', 'wrapper', 'write'],
  x: ['xhr', 'xml', 'xray'],
  y: ['yield', 'year'],
  z: ['zone', 'zero'],
};

function recoverNames(inputCode) {
  const names = [];
  const shortRe = /\b(?:var|let|const)\s+([a-z])\s*[=;]/gi;
  let m;
  while ((m = shortRe.exec(inputCode)) !== null) {
    const ch = m[1].toLowerCase();
    if (!names.find(n => n.original === m[1])) {
      const suggestions = NGRAM_MAP[ch] || [`${ch}_value`];
      names.push({ original: m[1], suggestions, line: inputCode.substring(0, m.index).split('\n').length });
    }
  }

  const hexRe = /(_0x[a-f0-9]{4,6})\b/g;
  const seen = new Set();
  while ((m = hexRe.exec(inputCode)) !== null) {
    if (!seen.has(m[1])) {
      seen.add(m[1]);
      names.push({ original: m[1], suggestions: ['obfuscated'], hint: 'hex-encoded name', line: inputCode.substring(0, m.index).split('\n').length });
    }
  }

  return { names, total: names.length };
}

if (isCLI) {
  const result = recoverNames(code);
  console.log(`\n========================================`);
  console.log(`  Minified Name Recovery`);
  console.log(`========================================`);
  console.log(`  Names found: ${result.total}`);
  const singles = result.names.filter(n => n.original.length === 1);
  if (singles.length > 0) {
    console.log('\n  Single-char suggestions:');
    singles.slice(0, 20).forEach(n => console.log(`    ${n.original} → ${n.suggestions[0]} (line ${n.line})`));
  }
  const hexes = result.names.filter(n => n.original.startsWith('_0x'));
  if (hexes.length > 0) {
    console.log(`\n  Hex-encoded names: ${hexes.length}`);
    console.log(`    Indicating javascript-obfuscator / obfuscator.io`);
  }
  console.log('');
}

module.exports = { recoverNames, NGRAM_MAP };
