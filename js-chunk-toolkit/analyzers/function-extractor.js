const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node function-extractor.js <file_or_dir> [--output report.json] [--webpack-stats]');
  console.log('  Extracts functions/modules from JS bundles (minified & readable).');
  console.log('  --webpack-stats  Output in webpack stats JSON format (compatible with webpack-bundle-analyzer)');
  process.exit(1);
}

const webpackStatsFlag = args.includes('--webpack-stats');
if (webpackStatsFlag) { args.splice(args.indexOf('--webpack-stats'), 1); }

const inputPath = args[0];
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : null;

function loadFiles(p) {
  if (!fs.existsSync(p)) { console.error(`Path not found: ${p}`); process.exit(1); }
  if (fs.statSync(p).isDirectory()) {
    const result = [];
    const loaded = harden.safeLoadFiles(p, ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx']);
    if (loaded.ok) {
      for (const f of loaded.files) {
        if (f.note?.includes('skipped')) { console.error(`  [!] Skipping ${f.name}: ${f.note}`); continue; }
        result.push({ name: f.name, filePath: f.filePath, content: f.content });
      }
    }
    for (const err of loaded.errors) console.error(`  [!] ${err}`);
    return result;
  }
  const loaded = harden.safeLoadFile(p);
  if (!loaded.ok) { console.error(`  [!] ${p}: ${loaded.error}`); process.exit(1); }
  return [{ name: path.basename(p), filePath: p, content: loaded.content }];
}

function extractBracketBlock(content, startIdx) {
  if (content[startIdx] !== '{') return -1;
  let depth = 0;
  let inString = false;
  let stringChar = null;
  for (let i = startIdx; i < content.length && i < startIdx + 100000; i++) {
    const ch = content[i];
    if (inString) {
      if (ch === '\\') { i++; continue; }
      if (ch === stringChar) inString = false;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') { inString = true; stringChar = ch; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

function getLineNumber(content, idx) {
  return content.substring(0, idx).split('\n').length;
}

function getFunctions(content) {
  const functions = [];
  const added = new Set();

  function addIfNew(name, type, params, startIdx, endIdx) {
    if (!name || name.length > 80 || added.has(name + startIdx)) return;
    added.add(name + startIdx);
    const line = getLineNumber(content, startIdx);
    const endLine = endIdx > 0 ? getLineNumber(content, endIdx) : line;
    const code = content.substring(startIdx, endIdx > 0 ? endIdx : startIdx + 1000);
    const signature = code.split('\n')[0].substring(0, 200);

    let complexity = 1;
    const codeBody = content.substring(content.indexOf('{', startIdx) + 1, endIdx > 0 ? endIdx - 1 : startIdx + 1000);
    const ifCount = (codeBody.match(/\bif\s*\(/g) || []).length;
    const loopCount = (codeBody.match(/\b(for|while|do)\s*\(/g) || []).length;
    const caseCount = (codeBody.match(/\bcase\s+/g) || []).length;
    const catchCount = (codeBody.match(/\bcatch\s*\(/g) || []).length;
    const andCount = (codeBody.match(/&&/g) || []).length;
    complexity += ifCount + loopCount + caseCount + catchCount + Math.min(andCount, 5);

    functions.push({
      name, type,
      params: params ? params.split(',').map(p => p.trim()).filter(Boolean) : [],
      line, endLine,
      linesOfCode: endLine - line + 1,
      complexity,
      signature,
      code: code.length > 800 ? code.substring(0, 800) + '\n  /* ... truncated ... */' : code
    });
  }

  function findWebpackModules(c) {
    const moduleRe = /[,{](\d{2,5}|[a-f0-9]{2,8})\s*:\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = moduleRe.exec(c)) !== null) {
      const name = `webpack:${m[1]}`;
      const params = m[2];
      const braceIdx = c.indexOf('{', m.index + m[0].lastIndexOf('{'));
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'webpack module', params, m.index, endBrace);
    }
  }

  function findWebpackArrowModules(c) {
    const arrowRe = /[,{](\d{2,5}|[a-f0-9]{2,8})\s*:\s*\(([^)]*)\)\s*=>\s*\{/g;
    let m;
    while ((m = arrowRe.exec(c)) !== null) {
      const name = `mod:${m[1]}`;
      const params = m[2];
      const arrowEnd = m.index + m[0].length - 1;
      if (c[arrowEnd] === '{') {
        const endBrace = extractBracketBlock(c, arrowEnd);
        addIfNew(name, 'webpack arrow module', params, m.index, endBrace);
      }
    }
  }

  function findArrowFuncs(c) {
    const arrowRe = /(?:^|[;={}(\[,\s+!&|?:])(?:async\s+)?\(?([\w$]+(?:,\s*[\w$]+)*)?\)?\s*=>\s*\{/g;
    let m;
    while ((m = arrowRe.exec(c)) !== null) {
      const before = c.substring(Math.max(0, m.index - 60), m.index);
      let name = 'anon';
      const nameMatch = before.match(/(?:const|let|var|,\s*)\s*(\w+)\s*=\s*(?:async\s+)?$/);
      if (nameMatch) name = nameMatch[1];
      else if (m[1]) name = m[1].split(',')[0].trim();
      if (name === 'anon' || name.length > 30) continue;

      const arrowIdx = c.indexOf('=>', m.index);
      const braceIdx = c.indexOf('{', arrowIdx);
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'arrow function', m[1] || '', m.index, endBrace);
    }
  }

  function findNamedFunc(c) {
    const funcRe = /(?:^|[;={}(\[,\s!&|?:])(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = funcRe.exec(c)) !== null) {
      const name = m[1];
      const braceIdx = c.indexOf('{', m.index + m[0].indexOf('{', 10));
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'function declaration', m[2], m.index, endBrace);
    }
  }

  function findVarFunc(c) {
    const varRe = /(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = varRe.exec(c)) !== null) {
      const name = m[1];
      const braceIdx = c.indexOf('{', m.index + m[0].lastIndexOf('{'));
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'var-assigned function', m[2], m.index, endBrace);
    }
  }

  function findClassMethods(c) {
    const methodRe = /(?:^|[;={}\s])(\w+)\s*\(([^)]*)\)\s*\{/g;
    let m;
    const SKIP = ['if', 'else', 'for', 'while', 'do', 'switch', 'catch', 'function', 'then', 'else', 'map', 'filter', 'reduce', 'forEach', 'find', 'some', 'every', 'return', 'typeof', 'delete', 'void', 'new', 'throw', 'import', 'export', 'default', 'extends', 'in', 'of', 'from'];
    while ((m = methodRe.exec(c)) !== null) {
      const name = m[1];
      if (SKIP.includes(name) || name.length > 40 || /^[A-Z_0-9]+$/.test(name)) continue;
      const before = c.substring(Math.max(0, m.index - 80), m.index);
      if (/[{},;]\s*$/.test(before) || /\bclass\s/.test(before)) {
        const braceIdx = m.index + m[0].lastIndexOf('{');
        const endBrace = extractBracketBlock(c, braceIdx);
        const typeMatch = before.match(/\b(class|prototype)\s/);
        addIfNew(name, typeMatch ? 'class method' : 'object method', m[2], m.index, endBrace);
      }
    }
  }

  function findConstructor(c) {
    const ctorRe = /constructor\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = ctorRe.exec(c)) !== null) {
      const braceIdx = m.index + m[0].lastIndexOf('{');
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew('constructor', 'class constructor', m[1], m.index, endBrace);
    }
  }

  function findGetterSetters(c) {
    const gsRe = /\b(get|set)\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = gsRe.exec(c)) !== null) {
      const name = `${m[1]} ${m[2]}`;
      const braceIdx = c.indexOf('{', m.index);
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'getter/setter', m[3], m.index, endBrace);
    }
  }

  function findExportedFuncs(c) {
    const expRe = /(?:exports|module\.exports|export default)\s*\.?\s*(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = expRe.exec(c)) !== null) {
      const name = m[1];
      const braceIdx = c.indexOf('{', m.index);
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'exported function', m[2], m.index, endBrace);
    }
  }

  function findGeneratorFuncs(c) {
    const genRe = /(?:^|[;={}\s])function\s*\*\s*(\w*)\s*\(([^)]*)\)\s*\{/g;
    let m;
    while ((m = genRe.exec(c)) !== null) {
      const name = m[1] || 'anon_generator';
      const braceIdx = c.indexOf('{', m.index);
      const endBrace = extractBracketBlock(c, braceIdx);
      addIfNew(name, 'generator', m[2], m.index, endBrace);
    }
  }

  findWebpackModules(content);
  findWebpackArrowModules(content);
  findNamedFunc(content);
  findVarFunc(content);
  findArrowFuncs(content);
  findClassMethods(content);
  findConstructor(content);
  findGetterSetters(content);
  findExportedFuncs(content);
  findGeneratorFuncs(content);

  functions.sort((a, b) => a.line - b.line);
  return functions;
}

// Feature: Extract IIFEs
function findIIFEs(content) {
  const iifeRe = /(?:^|[\s;({,=!&|?:+])(?:async\s+)?function\s*(?:\w+\s*)?\(([^)]*)\)\s*\{\s*(?:[^}]*)\}\s*\)\s*\(/g;
  const results = [];
  let m;
  while ((m = iifeRe.exec(content)) !== null) {
    const before = content.substring(Math.max(0, m.index - 40), m.index).trim();
    const type = before.endsWith('!') ? 'IIFE (immediately)' : 'IIFE';
    results.push({ type, params: m[1], line: getLineNumber(content, m.index) });
    if (results.length > 200) break;
  }
  return results;
}

// Feature: Extract exported functions (ESM style)
function findESMExports(content) {
  const results = [];
  const expRe = /export\s+(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\(/g;
  let m;
  while ((m = expRe.exec(content)) !== null) {
    results.push({ name: m[1], line: getLineNumber(content, m.index), type: 'ESM export' });
  }
  const arrExpRe = /export\s+(?:default\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(/g;
  while ((m = arrExpRe.exec(content)) !== null) {
    results.push({ name: m[1], line: getLineNumber(content, m.index), type: 'ESM arrow export' });
  }
  return results;
}

// Feature: Callback pattern analysis
function findCallbackPatterns(content) {
  const results = {};
  const patterns = [
    { name: 'Promise .then()', re: /\.then\s*\(\s*(?:function\s*\(|\([^)]*\)\s*=>)/g },
    { name: 'Promise .catch()', re: /\.catch\s*\(\s*(?:function\s*\(|\([^)]*\)\s*=>)/g },
    { name: 'Promise .finally()', re: /\.finally\s*\(\s*(?:function\s*\(|\([^)]*\)\s*=>)/g },
    { name: 'setTimeout callback', re: /setTimeout\s*\(\s*(?:function\s*\(|\([^)]*\)\s*=>)/g },
    { name: 'setInterval callback', re: /setInterval\s*\(\s*(?:function\s*\(|\([^)]*\)\s*=>)/g },
    { name: 'addEventListener', re: /addEventListener\s*\(\s*['"][^'"]+['"]\s*,\s*(?:function|\([^)]*\)\s*=>)/g },
    { name: 'Array callback (.map/.filter/.reduce)', re: /\.(?:map|filter|reduce|forEach|find|some|every)\s*\(\s*(?:function|\([^)]*\)\s*=>)/g },
    { name: 'RxJS observable', re: /\.(?:subscribe|pipe|switchMap|mergeMap|concatMap)\s*\(\s*(?:function|\([^)]*\)\s*=>)/g },
  ];
  for (const p of patterns) {
    const matches = content.match(p.re);
    if (matches) results[p.name] = matches.length;
  }
  return results;
}

// Feature: Async/await analysis
function analyzeAsyncPatterns(content) {
  const totalAsync = (content.match(/\basync\b/g) || []).length;
  const totalAwait = (content.match(/\bawait\b/g) || []).length;
  const promiseAll = (content.match(/Promise\.all\s*\(/g) || []).length;
  const promiseRace = (content.match(/Promise\.race\s*\(/g) || []).length;
  const promiseAllSettled = (content.match(/Promise\.allSettled\s*\(/g) || []).length;
  const promiseAny = (content.match(/Promise\.any\s*\(/g) || []).length;
  return { totalAsync, totalAwait, promiseAll, promiseRace, promiseAllSettled, promiseAny };
}

// Feature: Function depth analysis
function estimateDepth(content) {
  let maxDepth = 0;
  let depth = 0;
  let inString = false;
  let strChar = null;
  const re = /[{}]/g;
  let m;
  while ((m = re.exec(content)) !== null) {
    if (inString) { continue; }
    const ch = m[0];
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    if (depth > maxDepth) maxDepth = depth;
    if (maxDepth > 50) break;
  }
  return maxDepth;
}

// Feature: Unique function name analysis
function analyzeFunctionNames(functions) {
  const nameCounts = {};
  for (const f of functions) {
    const base = f.name.includes(':') ? f.name.split(':')[1] : f.name;
    if (base && !['anon', 'constructor'].includes(base) && base.length < 60) {
      nameCounts[base] = (nameCounts[base] || 0) + 1;
    }
  }
  const dupes = Object.entries(nameCounts).filter(([, c]) => c > 1).sort((a, b) => b[1] - a[1]);
  return { totalUnique: Object.keys(nameCounts).length, duplicateNames: dupes.slice(0, 20) };
}

// Feature: Argument count distribution
function calcArgDistribution(functions) {
  const dist = {};
  for (const f of functions) {
    const count = f.params.length;
    const key = count > 5 ? '6+' : String(count);
    dist[key] = (dist[key] || 0) + 1;
  }
  return dist;
}

// Feature: Function size buckets
function calcSizeBuckets(functions) {
  const buckets = { '0-10': 0, '11-30': 0, '31-100': 0, '101-300': 0, '301+': 0 };
  for (const f of functions) {
    if (f.linesOfCode <= 10) buckets['0-10']++;
    else if (f.linesOfCode <= 30) buckets['11-30']++;
    else if (f.linesOfCode <= 100) buckets['31-100']++;
    else if (f.linesOfCode <= 300) buckets['101-300']++;
    else buckets['301+']++;
  }
  return buckets;
}

const files = loadFiles(inputPath);
const allFunctions = {};
const stats = { totalFiles: files.length, totalFunctions: 0, byType: {}, byComplexity: { simple: 0, medium: 0, high: 0, very_high: 0 }, totalLines: 0 };

files.forEach(({ name, content }) => {
  const functions = getFunctions(content);
  if (functions.length === 0) return;
  allFunctions[name] = functions;
  stats.totalFunctions += functions.length;

  functions.forEach(f => {
    if (!stats.byType[f.type]) stats.byType[f.type] = 0;
    stats.byType[f.type]++;
    stats.totalLines += f.linesOfCode;

    if (f.complexity > 20) stats.byComplexity.very_high++;
    else if (f.complexity > 10) stats.byComplexity.high++;
    else if (f.complexity > 5) stats.byComplexity.medium++;
    else stats.byComplexity.simple++;
  });
});

const sorted = [];
Object.entries(allFunctions).forEach(([file, funcs]) => {
  funcs.forEach(f => sorted.push({ file, ...f }));
});
sorted.sort((a, b) => b.complexity - a.complexity);

console.log('');
console.log('========================================');
console.log('  Function Extractor Results');
console.log('========================================');
console.log(`  Files analyzed:     ${stats.totalFiles}`);
console.log(`  Files with funcs:   ${Object.keys(allFunctions).length}`);
console.log(`  Total functions:    ${stats.totalFunctions}`);
console.log(`  Average LOC/func:   ${stats.totalFunctions > 0 ? Math.round(stats.totalLines / stats.totalFunctions) : 0}`);
console.log('');
console.log('  Function types:');
Object.entries(stats.byType).sort((a, b) => b[1] - a[1]).forEach(([type, count]) => {
  const pct = count > 0 ? Math.round(count / stats.totalFunctions * 100) : 0;
  console.log(`    ${type.padEnd(28)}: ${count.toString().padStart(5)} (${pct}%)`);
});
console.log('');
console.log('  Complexity distribution:');
Object.entries(stats.byComplexity).sort((a, b) => b[1] - a[1]).forEach(([range, count]) => {
  const pct = count > 0 ? Math.round(count / stats.totalFunctions * 100) : 0;
  console.log(`    ${range.padEnd(15)}: ${count.toString().padStart(5)} (${pct}%)`);
});

const allFuncs = sorted.map(s => ({ name: s.name, type: s.type, params: s.params, complexity: s.complexity, linesOfCode: s.linesOfCode, file: s.file, line: s.line, signature: s.signature }));

console.log('');
console.log('  Argument count distribution:');
const argDist = calcArgDistribution(sorted);
Object.entries(argDist).sort((a, b) => a[0] === '0' ? -1 : parseInt(a[0]) - parseInt(b[0])).forEach(([count, n]) => {
  console.log(`    ${count.padEnd(6)} args: ${n} functions`);
});

console.log('');
console.log('  Function size (LOC) distribution:');
const sizeBuckets = calcSizeBuckets(sorted);
Object.entries(sizeBuckets).forEach(([range, n]) => {
  const pct = n > 0 ? Math.round(n / sorted.length * 100) : 0;
  console.log(`    ${range.padEnd(8)} lines: ${n.toString().padStart(5)} (${pct}%)`);
});

console.log('');
console.log('  Unique function names:');
const nameAnalysis = analyzeFunctionNames(sorted);
console.log(`    Total unique: ${nameAnalysis.totalUnique}`);
if (nameAnalysis.duplicateNames.length > 0) {
  console.log(`    Most duplicated:`);
  nameAnalysis.duplicateNames.slice(0, 10).forEach(([name, count]) => {
    console.log(`      "${name}" appears ${count} times`);
  });
}

const totalContent = files.map(f => f.content).join('\n');
const iifes = findIIFEs(totalContent);
const esmExports = findESMExports(totalContent);
const asyncPat = analyzeAsyncPatterns(totalContent);
const callbackPat = findCallbackPatterns(totalContent);
const maxDepth = estimateDepth(totalContent);

console.log('');
console.log('  IIFE count:');
console.log(`    ${iifes.length} IIFE(s) found`);
console.log('');
console.log('  ESM export count:');
console.log(`    ${esmExports.length} ESM export(s)`);
console.log('');
console.log('  Async/await patterns:');
console.log(`    async keywords:     ${asyncPat.totalAsync}`);
console.log(`    await keywords:     ${asyncPat.totalAwait}`);
console.log(`    Promise.all:        ${asyncPat.promiseAll}`);
console.log(`    Promise.race:       ${asyncPat.promiseRace}`);
console.log(`    Promise.allSettled: ${asyncPat.promiseAllSettled}`);
console.log(`    Promise.any:        ${asyncPat.promiseAny}`);
console.log('');
console.log('  Callback patterns:');
if (Object.keys(callbackPat).length > 0) {
  Object.entries(callbackPat).sort((a, b) => b[1] - a[1]).forEach(([name, count]) => {
    console.log(`    ${name.padEnd(35)}: ${count}`);
  });
} else { console.log(`    None detected`); }
console.log('');
console.log('  Max nesting depth:');
console.log(`    ${maxDepth} levels`);
console.log('');

console.log('  Top 10 most complex functions:');
sorted.slice(0, 10).forEach((f, i) => {
  const shortName = f.name.length > 42 ? f.name.substring(0, 39) + '...' : f.name;
  console.log(`    ${(i+1).toString().padStart(2)}. ${shortName.padEnd(46)} (cyc:${f.complexity}, ${f.linesOfCode}l) [${f.file}:${f.line}]`);
});

if (outputPath) {
  const outData = {
    metadata: { date: new Date().toISOString(), ...stats,
      iifesFound: iifes.length,
      esmExports: esmExports.length,
      maxNestingDepth: maxDepth,
      asyncPatterns: asyncPat,
      callbackPatterns: callbackPat,
      argDistribution: argDist,
      sizeBuckets,
      uniqueNames: nameAnalysis.totalUnique,
      duplicateNames: nameAnalysis.duplicateNames.slice(0, 20)
    },
    topComplex: allFuncs.slice(0, 50),
    iifes: iifes.slice(0, 100),
    esmExports: esmExports.slice(0, 100),
    byFile: {}
  };
  Object.entries(allFunctions).forEach(([file, funcs]) => {
    outData.byFile[file] = funcs.map(f => ({
      name: f.name, type: f.type, params: f.params,
      line: f.line, endLine: f.endLine,
      linesOfCode: f.linesOfCode, complexity: f.complexity,
      signature: f.signature
    }));
  });
  if (webpackStatsFlag) {
    const wpStats = {
      version: '5.0.0',
      hash: require('crypto').createHash('md5').update(JSON.stringify(outData)).digest('hex').substring(0, 20),
      modules: []
    };
    for (const [file, funcs] of Object.entries(allFunctions)) {
      for (const f of funcs) {
        wpStats.modules.push({
          id: `${file}/${f.name}`,
          name: `${file}#${f.name}`,
          size: f.linesOfCode * 40,
          chunks: ['main'],
          moduleType: f.type === 'arrow' ? 'esm' : 'cjs',
          identifier: f.signature
        });
      }
    }
    wpStats.modules.sort((a, b) => b.size - a.size);
    fs.writeFileSync(outputPath, JSON.stringify(wpStats, null, 2));
    console.log(`\n[OK] Webpack stats written to ${outputPath} (${wpStats.modules.length} modules)`);
  } else {
    fs.writeFileSync(outputPath, JSON.stringify(outData, null, 2));
    console.log(`\n[OK] Function extraction written to ${outputPath}`);
  }
}