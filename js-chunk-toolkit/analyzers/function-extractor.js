const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node function-extractor.js <file_or_dir> [--output report.json]');
  console.log('  Extracts functions/modules from JS bundles (minified & readable).');
  process.exit(1);
}

const inputPath = args[0];
const outputFlag = args.indexOf('--output');
const outputPath = outputFlag > -1 && args[outputFlag + 1] ? args[outputFlag + 1] : null;

function loadFiles(p) {
  if (!fs.existsSync(p)) { console.error(`Path not found: ${p}`); process.exit(1); }
  if (fs.statSync(p).isDirectory()) {
    const result = [];
    function walk(dir) {
      fs.readdirSync(dir).forEach(f => {
        const fp = path.join(dir, f);
        if (fs.statSync(fp).isDirectory()) walk(fp);
        else if (/\.(js|mjs|cjs|jsx|ts|tsx)$/i.test(f)) {
          try { result.push({ name: path.relative(inputPath, fp), filePath: fp, content: fs.readFileSync(fp, 'utf-8') }); }
          catch (e) { console.error(`  [!] Skipping ${fp}: ${e.message}`); }
        }
      });
    }
    walk(p);
    return result;
  }
  return [{ name: path.basename(p), filePath: p, content: fs.readFileSync(p, 'utf-8') }];
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

console.log('');
console.log('  Top 10 most complex functions:');
sorted.slice(0, 10).forEach((f, i) => {
  const shortName = f.name.length > 42 ? f.name.substring(0, 39) + '...' : f.name;
  console.log(`    ${(i+1).toString().padStart(2)}. ${shortName.padEnd(46)} (cyc:${f.complexity}, ${f.linesOfCode}l) [${f.file}:${f.line}]`);
});

if (outputPath) {
  const outData = {
    metadata: { date: new Date().toISOString(), ...stats },
    topComplex: sorted.slice(0, 50).map(f => ({
      name: f.name, type: f.type, params: f.params,
      file: f.file, line: f.line, endLine: f.endLine,
      linesOfCode: f.linesOfCode, complexity: f.complexity,
      signature: f.signature
    })),
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
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(outData, null, 2));
  console.log(`\n[OK] Function extraction written to ${outputPath}`);
}