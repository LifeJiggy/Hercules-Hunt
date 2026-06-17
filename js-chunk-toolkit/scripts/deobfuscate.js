const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PACKER_DETECTORS = [
  { name: 'Minified Only', test: (c) => /^!?function\(\w,\w,\w\)\{/.test(c.trim().substring(0, 200)) },
  { name: 'Webpack', test: (c) => /__webpack_require__/.test(c) },
  { name: 'javascript-obfuscator', test: (c) => /_0x[a-f0-9]{4,6}.+\[.+\].+\(/.test(c) },
  { name: 'obfuscator.io', test: (c) => /_0x[a-f0-9]+ = !!\[]/.test(c) },
  { name: 'JSFuck', test: (c) => /^[\[\]()!+]+$/.test(c.substring(0, 1000)) },
  { name: 'aaencode', test: (c) => /[ﾟωﾉ｀´ﾟ]/.test(c) },
  { name: 'jjencode', test: (c) => /\$\s*=\s*~\[\]/.test(c) },
  { name: 'Packer (eval+p,a,c,k,e,d)', test: (c) => /eval\(function\s*\(p,a,c,k,e,d\)/.test(c) },
  { name: 'Control Flow Flattened', test: (c) => /while\s*\(\s*!?\s*true\s*\).+switch\s*\(\s*\w+\s*\)/.test(c) },
  { name: 'eval/Function Heavy', test: (c) => /(?:eval|new\s+Function|setTimeout)\s*\([^)]{50,}/.test(c) },
  { name: 'Base64 Heavy', test: (c) => /atob\([^)]{30,}/.test(c) },
  { name: 'String Array Based', test: (c) => /var\s+\w+\s*=\s*\[.+\].+\((\w+,\w+)\)/.test(c) },
  { name: 'Jscrambler', test: (c) => /(S139|S162|S182|S219)|Jscrambler/.test(c) },
];

function detectObfuscation(code) {
  const detected = [];
  for (const d of PACKER_DETECTORS) {
    if (d.test(code)) detected.push(d.name);
  }
  return detected.length ? detected : ['Unknown / Custom'];
}

function extractStringArrays(code) {
  const results = [];
  const arrayRegex = /(?:var|let|const)\s+(\w+)\s*=\s*\[([^\]]+?)\];/gs;
  let match;
  while ((match = arrayRegex.exec(code)) !== null) {
    const items = match[2].match(/"([^"]*)"|'([^']*)'/g);
    if (items && items.length > 3) {
      results.push({
        name: match[1],
        items: items.map(i => i.slice(1, -1)),
      });
    }
  }
  return results;
}

function extractBase64Strings(code) {
  const results = [];
  const b64Regex = /["']([A-Za-z0-9+/=]{20,})["']/g;
  let match;
  while ((match = b64Regex.exec(code)) !== null) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
      if (decoded.length > 3 && /[a-zA-Z]{4,}/.test(decoded)) {
        results.push({ encoded: match[1].substring(0, 40) + '...', decoded: decoded.substring(0, 200) });
      }
    } catch (e) {}
  }
  return results;
}

function extractHexStrings(code) {
  const results = [];
  const hexRegex = /"(\\x[0-9a-f]{2}){4,}"/gi;
  let match;
  while ((match = hexRegex.exec(code)) !== null) {
    try {
      const decoded = match[0].replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      const cleaned = decoded.replace(/^"|"$/g, '');
      if (cleaned.length > 3) results.push(cleaned);
    } catch (e) {}
  }
  return results;
}

function extractUnicodeStrings(code) {
  const results = [];
  const uniRegex = /"(\\u[0-9a-f]{4}){2,}"/gi;
  let match;
  while ((match = uniRegex.exec(code)) !== null) {
    try {
      const decoded = JSON.parse(match[0].replace(/\\u([0-9a-f]{4})/gi, (_, h) => '\\u' + h));
      if (decoded.length > 3) results.push(decoded);
    } catch (e) {}
  }
  return results;
}

function extractFromCharCode(code) {
  const results = [];
  const fccRegex = /String\.fromCharCode\(([\d,\s]+)\)/g;
  let match;
  while ((match = fccRegex.exec(code)) !== null) {
    try {
      const nums = match[1].split(',').map(Number);
      const decoded = String.fromCharCode(...nums);
      if (decoded.length > 3) results.push(decoded);
    } catch (e) {}
  }
  return results;
}

function extractAtobCalls(code) {
  const results = [];
  const atobRegex = /atob\(["']([^"']+)["']\)/g;
  let match;
  while ((match = atobRegex.exec(code)) !== null) {
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
      results.push({ input: match[1].substring(0, 40), decoded: decoded.substring(0, 200) });
    } catch (e) {}
  }
  return results;
}

function extractWebpackModules(code) {
  const results = [];
  const modulePathRegex = /"((?:\.\/)?[^"]+(?:js|ts|jsx|tsx|json))":\s*function/g;
  let match;
  while ((match = modulePathRegex.exec(code)) !== null) {
    results.push(match[1]);
  }
  if (results.length === 0) {
    const idRegex = /"(\d+)":\s*function/g;
    while ((match = idRegex.exec(code)) !== null) {
      results.push(`module_${match[1]}`);
    }
  }
  return results;
}

function extractWebpackChunks(code) {
  const results = [];
  const chunkRegex = /["']([a-f0-9]{8,}\.js)["']/g;
  let match;
  while ((match = chunkRegex.exec(code)) !== null) {
    results.push(match[1]);
  }
  const publicPathMatch = code.match(/__webpack_require__\.p\s*=\s*["']([^"']+)["']/);
  if (publicPathMatch) results.push(`publicPath: ${publicPathMatch[1]}`);
  return results;
}

function extractStringsLongerThan(code, minLen = 30) {
  const results = [];
  const strRegex = new RegExp('["\'`]([^"\'`]{' + minLen + ',})["\'`]', 'g');
  let match;
  while ((match = strRegex.exec(code)) !== null) {
    const s = match[1];
    if (!/^[A-Za-z0-9+/=]+$/.test(s) && s.length < 500) results.push(s);
  }
  return [...new Set(results)];
}

// -- Feature 10: Anti-Debugger Detection --
function detectAntiDebug(code) {
  const results = [];
  const patterns = [
    { type: 'debugger; Statement', re: /\bdebugger\s*;/g },
    { type: 'DevTools Check', re: /(?:devtools|dev_tools|DevTools)\./gi },
    { type: 'console.profile Check', re: /console\.(profile|profileEnd)\s*\(/g },
    { type: 'performance.now() Timing', re: /performance\s*\.\s*now\s*\(/g },
    { type: 'toString Detection', re: /\b([a-z_]\w*)\s*\[\s*["']\1["']\s*\]/gi },
    { type: 'Firebug Check', re: /window\.console\.firebug|(?:firebug|Firebug)/g },
    { type: 'Chrome DevTools Protocol', re: /\/json\/version|\/json\/list|\/json\/protocol/g },
    { type: 'Debugger Enable Check', re: /(?:Debugger\.enable|Debugger\.disable|Debug\.enabled)/gi },
    { type: 'Stack Trace Inspection', re: /(?:Error|ErrorEvent)\.stack|console\.trace/g },
    { type: 'Timer Interference Check', re: /setTimeout\s*\(\s*["']debugger["']/gi },
    { type: 'Keyboard Shortcut Trap', re: /\.ctrlKey\s*&&\s*\.shiftKey\s*&&\s*\.which\s*===\s*73|F12|F12|devtoolsopen/gi },
  ];
  for (const p of patterns) {
    let match;
    while ((match = p.re.exec(code)) !== null) {
      results.push({ type: p.type, match: match[0].substring(0, 60), pos: match.index });
    }
  }
  return results;
}

// -- Feature 11: Self-Defending / Integrity Check Detection --
function detectSelfDefending(code) {
  const results = [];
  const patterns = [
    { type: 'Integrity Hash Check', re: /(?:sha|hash|integrity|checksum)\s*[:=]\s*["'][a-f0-9]{32,}["']/gi },
    { type: 'Source Map Validation', re: /sourcesContent\s*\[\s*\d+\s*\]\s*!==\s*/g },
    { type: 'Domain Lock Check', re: /(?:\blocation\b|\.host|\.hostname)\s*(?:!==|===|!=|==)\s*["']/g },
    { type: 'Cookie Expiry Check', re: /cookie\s*=\s*[^;]+;\s*max-age\s*=\s*0/gi },
    { type: 'LocalStorage Tamper Check', re: /localStorage\s*\.\s*getItem\s*\([^)]+\)\s*(?:===|!==)\s*["']/gi },
    { type: 'Extension Check', re: /chrome\s*\.\s*runtime\s*\.\s*id|browser\s*\.\s*runtime/i },
    { type: 'AdBlock Detection', re: /(?:adblock|adBlock|AdBlock|uBlock)/gi },
    { type: 'VM Detection', re: /(?:virtual|vmware|virtualbox|qemu|hyper-v|kvm)/gi },
    { type: 'Proxy Check', re: /(?:proxy|Proxy|HTTP_PROXY|HTTPS_PROXY)/gi },
    { type: 'Code Integrity Check', re: /(?:\bself\b|\bthis\b)\s*\[\s*["'](?:toString|toSource|constructor)["']\s*\]\s*[\(!]/g },
  ];
  for (const p of patterns) {
    let match;
    while ((match = p.re.exec(code)) !== null) {
      results.push({ type: p.type, match: match[0].substring(0, 80), pos: match.index });
    }
  }
  return results;
}

// -- Feature 12: Eval String Extraction & Recursive Deobfuscation --
function extractEvalStrings(code) {
  const results = [];
  const patterns = [
    { label: 'eval()', re: /eval\s*\(\s*["'`]([^"'`]{30,})["'`]\s*\)/g },
    { label: 'new Function()', re: /new\s+Function\s*\(\s*["'`]([^"'`]{30,})["'`]\s*\)/g },
    { label: 'setTimeout(string)', re: /setTimeout\s*\(\s*["'`]([^"'`]{30,})["'`]\s*\)/g },
    { label: 'setInterval(string)', re: /setInterval\s*\(\s*["'`]([^"'`]{30,})["'`]\s*\)/g },
    { label: 'execScript', re: /execScript\s*\(\s*["'`]([^"'`]{30,})["'`]\s*\)/g },
  ];
  for (const p of patterns) {
    let match;
    while ((match = p.re.exec(code)) !== null) {
      const decoded = match[1].replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)));
      results.push({
        type: p.label,
        raw: match[1].substring(0, 100),
        decoded: decoded !== match[1] ? decoded.substring(0, 200) : null,
        length: match[1].length,
      });
    }
  }
  return results;
}

// -- Feature 13: Nested/Multi-Layer Obfuscation Detection --
function detectNestedObfuscation(code) {
  const results = [];
  const signatures = [
    { name: 'Base64 Wrapper', re: /^[\s;]*["']?[A-Za-z0-9+/=]{50,}["']?[\s;]*$/m },
    { name: 'Eval Wrapper', re: /eval\s*\(\s*eval\s*\(/g },
    { name: 'Double Packer', re: /eval\(function\s*\(p,a,c,k,e,d\).*eval\(function\s*\(p,a,c,k,e,d\)/gs },
    { name: 'Recursive Decode Chain', re: /(?:atob|decodeURIComponent|unescape)\s*\(\s*(?:atob|decodeURIComponent|unescape)\s*\(/g },
    { name: 'Multi-layer Proxy', re: /function\s*\(\s*\w+\s*\)\s*\{[^}]*return\s*\w+\s*\(/g },
  ];
  for (const sig of signatures) {
    let count = 0;
    let match;
    while ((match = sig.re.exec(code)) !== null) count++;
    if (count > 0) results.push({ type: sig.name, count });
  }
  const layerEstimate = results.reduce((sum, r) => sum + r.count, 0);
  return { layers: results, estimate: Math.min(layerEstimate + 1, 10) };
}

// -- Feature 14: Variable Naming Entropy Analysis --
function analyzeVariableNames(code) {
  const results = [];
  const varPatterns = [
    { label: 'Single-char names', re: /\b(?:var|let|const)\s+([a-z])\s*[=;]/gi },
    { label: 'Hex names', re: /\b(?:var|let|const)\s+(_0x[a-f0-9]{4,})\s*[=;]/gi },
    { label: 'Short names (2 chars)', re: /\b(?:var|let|const)\s+([a-z]{2})\s*[=;]/gi },
    { label: 'Underscore prefix', re: /\b(?:var|let|const)\s+(_+[a-z]\w*)\s*[=;]/gi },
  ];
  for (const p of varPatterns) {
    let match;
    const names = new Set();
    while ((match = p.re.exec(code)) !== null) names.add(match[1]);
    if (names.size > 0) results.push({ type: p.label, count: names.size, examples: [...names].slice(0, 10) });
  }

  const params = code.match(/function\s*\w*\s*\(\s*([^)]+)\)/g);
  if (params) {
    let singleChar = 0; let total = 0;
    params.forEach(p => {
      p.replace(/[a-z]\b/g, () => { total++; });
      p.replace(/[a-z]\b/g, () => { total++; });
    });
  }

  const hexVars = code.match(/_0x[a-f0-9]{4,}/g);
  if (hexVars) results.push({ type: 'Hex variable references', count: hexVars.length });

  return results;
}

// -- Feature 15: Control Flow Flattening Recovery Points --
function detectControlFlowFlattening(code) {
  const results = [];
  const patterns = [
    { label: 'Switch in While(true)', re: /while\s*\(\s*(?:1|!0|true)\s*\)\s*\{[\s\S]*?switch\s*\(\s*(\w+)\s*\)/g },
    { label: 'Dispatcher Variable', re: /(?:var|let|const)\s+(\w+)\s*=\s*\d+\s*[;,]/, follow: /switch\s*\(\s*\1\s*\)/g },
    { label: 'State Array', re: /\['?\d+'?\]\s*=\s*['"]?\d+['"]?\s*[,;][\s\S]{0,200}\[\d+\]\s*=\s*\d+/g },
  ];
  for (const p of patterns) {
    let match;
    while ((match = p.re.exec(code)) !== null) {
      results.push({ type: p.label, match: match[0].substring(0, 80) });
    }
  }
  return results;
}

// -- Feature 16: Hidden Payload Extraction --
function extractHiddenPayloads(code) {
  const results = [];
  const payloadPatterns = [
    { label: 'JSFuck-like', re: /^[\[\]()!+]{100,}$/m },
    { label: 'Decimal Encoded', re: /(?:\b|\D)(\d{3,7}(?:\s*,\s*\d{3,7}){3,})\b/g },
    { label: 'Chained atob', re: /atob\([^)]+\)\s*\+\s*atob\([^)]+\)/g },
    { label: 'Chained fromCharCode', re: /String\.fromCharCode\([^)]+\)\s*\+\s*String\.fromCharCode\([^)]+\)/g },
    { label: 'Reverse String', re: /\.split\(["']{2}["']\)\.reverse\(\)\.join\(["']{2}["']\)/g },
    { label: 'Char Code Array', re: /\[(\d{2,3}(?:\s*,\s*\d{2,3}){5,})\]/g },
    { label: 'XOR Encoded String', re: /\^0x[a-f0-9]{2,4}/gi },
    { label: 'RC4/Similar', re: /(?:function\s+\w*rc4|rc4\s*=|arcfour|salsa)/gi },
  ];
  for (const p of payloadPatterns) {
    let match;
    let count = 0;
    while ((match = p.re.exec(code)) !== null) count++;
    if (count > 0) results.push({ label: p.label, count });
  }
  return results;
}

// -- Feature 17: Unicode Homoglyph / Normalization Attack Detection --
function detectUnicodeAttacks(code) {
  const results = [];
  const patterns = [
    { label: 'Homoglyph Characters', re: /[а-яА-ЯοоΟΟρｃａｅ]/g },
    { label: 'Zero-Width Characters', re: /[\u200B\u200C\u200D\uFEFF\u2060]/g },
    { label: 'Right-to-Left Override', re: /\u202E/g },
    { label: 'Fullwidth Characters', re: /[Ａ-Ｚａ-ｚ０-９]/g },
    { label: 'Mathematical Script', re: /\uD835[\uDC00-\uDFFF]/g },
  ];
  for (const p of patterns) {
    let match;
    let count = 0;
    let lastIdx = -1;
    while ((match = p.re.exec(code)) !== null) { count++; lastIdx = match.index; }
    if (count > 0) {
      const sample = lastIdx >= 0 ? code.substring(Math.max(0, lastIdx - 10), Math.min(code.length, lastIdx + 20)).replace(/\s+/g, ' ') : '';
      results.push({ label: p.label, count, sample });
    }
  }
  return results;
}

// -- Feature 18: Section-Based Obfuscation Probability Scoring --
function scoreObfuscationSections(code) {
  const sections = [];
  const lines = code.split('\n');
  const chunkSize = Math.max(50, Math.floor(lines.length / 20));
  for (let i = 0; i < lines.length; i += chunkSize) {
    const chunk = lines.slice(i, i + chunkSize).join('\n');
    let score = 0;
    let reasons = [];
    const checks = [
      { weight: 3, label: 'hex variable', re: /_0x[a-f0-9]{4,}/g },
      { weight: 2, label: 'long eval', re: /eval\s*\([^)]{50,}/g },
      { weight: 1, label: 'fromCharCode', re: /fromCharCode/g },
      { weight: 2, label: 'base64 string', re: /["'][A-Za-z0-9+/=]{40,}["']/g },
      { weight: 3, label: 'control flow', re: /while\s*\(\s*!?1\s*\)/g },
      { weight: 1, label: 'short var', re: /\b(?:var|let|const)\s+[a-z]\b/g },
      { weight: 1, label: 'minified', re: /;!function|\}\(\)\);/g },
      { weight: 2, label: 'string array', re: /\w+\s*\[\s*\d+\s*\]\s*\(/g },
    ];
    for (const c of checks) {
      let m; let cnt = 0;
      while ((m = c.re.exec(chunk)) !== null) cnt++;
      if (cnt > 0) { score += c.weight * cnt; reasons.push(`${c.label}x${cnt}`); }
    }
    if (score > 0) {
      sections.push({ line: i + 1, score, severity: score > 15 ? 'HIGH' : score > 8 ? 'MEDIUM' : 'LOW', reasons: reasons.slice(0, 4) });
    }
  }
  return sections.sort((a, b) => b.score - a.score);
}

// -- Feature 19: Automated String Deobfuscation Pipeline --
function autoDeobfuscate(code) {
  const results = { decoded: code, steps: [], transforms: 0 };
  let current = code;
  let seen = new Set();
  for (let iter = 0; iter < 10; iter++) {
    if (seen.has(current)) break;
    seen.add(current);
    let changed = false;

    const hexMatch = current.match(/"(\\x[0-9a-f]{2}){4,}"/i);
    if (hexMatch) {
      try {
        const d = JSON.parse(hexMatch[0].replace(/\\x/g, '\\x'));
        current = current.replace(hexMatch[0], `"${d}"`);
        results.steps.push(`hex:${hexMatch[0].substring(0, 30)}`); changed = true;
      } catch (e) {}
    }

    const uniMatch = current.match(/"(\\u[0-9a-f]{4}){2,}"/i);
    if (uniMatch) {
      try {
        const d = JSON.parse(uniMatch[0]);
        current = current.replace(uniMatch[0], `"${d}"`);
        results.steps.push(`unicode:${uniMatch[0].substring(0, 30)}`); changed = true;
      } catch (e) {}
    }

    const fccMatch = current.match(/String\.fromCharCode\(([\d,\s]+)\)/g);
    if (fccMatch) {
      for (const fm of fccMatch) {
        try {
          const nums = fm.match(/\d+/g).map(Number);
          const d = String.fromCharCode(...nums);
          current = current.replace(fm, `"${d}"`);
          results.steps.push(`fromCharCode:${fm.substring(0, 40)}`); changed = true;
        } catch (e) {}
      }
    }

    const atobMatch = current.match(/atob\(["']([^"']+)["']\)/g);
    if (atobMatch) {
      for (const am of atobMatch) {
        try {
          const input = am.match(/["']([^"']+)["']/)[1];
          const d = Buffer.from(input, 'base64').toString('utf-8');
          current = current.replace(am, `"${d}"`);
          results.steps.push(`atob:${am.substring(0, 40)}`); changed = true;
        } catch (e) {}
      }
    }

    if (!changed) break;
    results.transforms++;
  }
  results.decoded = current;
  return results;
}

function scan(inputFile) {
  if (!fs.existsSync(inputFile)) {
    console.error(`File not found: ${inputFile}`);
    process.exit(1);
  }

  const code = fs.readFileSync(inputFile, 'utf-8');
  const filename = path.basename(inputFile);
  const sizeKB = (code.length / 1024).toFixed(1);

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  File: ${filename} (${sizeKB} KB)`);
  console.log(`${'='.repeat(70)}`);

  console.log(`\n[1] Obfuscation Detection`);
  console.log(`  ${'-'.repeat(50)}`);
  const types = detectObfuscation(code);
  types.forEach(t => console.log(`  ${t}`));

  if (code.includes('__webpack_require__')) {
    console.log(`\n[2] Webpack Module Map`);
    console.log(`  ${'-'.repeat(50)}`);
    const modules = extractWebpackModules(code);
    console.log(`  Total modules found: ${modules.length}`);
    if (modules.length > 0) {
      const interesting = modules.filter(m => /api|admin|internal|secret|token|config|auth|key/.test(m));
      if (interesting.length > 0) {
        console.log(`  Interesting modules:`);
        interesting.forEach(m => console.log(`    ${m}`));
      }
      modules.slice(0, 20).forEach(m => console.log(`    ${m}`));
      if (modules.length > 20) console.log(`    ... and ${modules.length - 20} more`);
    }

    console.log(`\n  Webpack Chunks:`);
    const chunks = extractWebpackChunks(code);
    chunks.forEach(c => console.log(`    ${c}`));
  }

  console.log(`\n[3] String Array Extraction`);
  console.log(`  ${'-'.repeat(50)}`);
  const arrays = extractStringArrays(code);
  if (arrays.length > 0) {
    arrays.forEach(arr => {
      console.log(`  Array "${arr.name}" (${arr.items.length} items)`);
      const interesting = arr.items.filter(i => /api|http|secret|token|key|admin|graphql|firebase|auth/.test(i));
      interesting.slice(0, 30).forEach(i => console.log(`    -> ${i.substring(0, 120)}`));
      if (interesting.length > 30) console.log(`    ... and ${interesting.length - 30} more`);
    });
  } else {
    console.log(`  No string arrays detected (or pattern not matched)`);
  }

  console.log(`\n[4] Base64-Encoded Strings (potential secrets)`);
  console.log(`  ${'-'.repeat(50)}`);
  const b64 = extractBase64Strings(code);
  if (b64.length > 0) {
    const interesting = b64.filter(b => /http|api|secret|token|key|admin|firebase|graphql|auth/.test(b.decoded));
    interesting.slice(0, 30).forEach(b => {
      console.log(`  ${b.decoded.substring(0, 150)}`);
    });
    if (interesting.length > 30) console.log(`  ... and ${interesting.length - 30} more`);
    console.log(`  Total base64 candidates: ${b64.length}`);
  } else {
    console.log(`  None found`);
  }

  console.log(`\n[5] Hex-Encoded Strings`);
  console.log(`  ${'-'.repeat(50)}`);
  const hex = extractHexStrings(code);
  hex.slice(0, 20).forEach(h => console.log(`  ${h.substring(0, 120)}`));
  if (hex.length === 0) console.log(`  None found`);

  console.log(`\n[6] Unicode-Escaped Strings`);
  console.log(`  ${'-'.repeat(50)}`);
  const uni = extractUnicodeStrings(code);
  uni.slice(0, 20).forEach(u => console.log(`  ${u.substring(0, 120)}`));
  if (uni.length === 0) console.log(`  None found`);

  console.log(`\n[7] String.fromCharCode Constructions`);
  console.log(`  ${'-'.repeat(50)}`);
  const fcc = extractFromCharCode(code);
  fcc.slice(0, 20).forEach(f => console.log(`  ${f.substring(0, 120)}`));
  if (fcc.length === 0) console.log(`  None found`);

  console.log(`\n[8] atob() Calls (Base64 decode)`);
  console.log(`  ${'-'.repeat(50)}`);
  const atobs = extractAtobCalls(code);
  atobs.slice(0, 20).forEach(a => console.log(`  ${a.decoded.substring(0, 150)}`));
  if (atobs.length === 0) console.log(`  None found`);

  console.log(`\n[9] Long String Literals (> 30 chars)`);
  console.log(`  ${'-'.repeat(50)}`);
  const longStrs = extractStringsLongerThan(code, 30);
  const interesting = longStrs.filter(s => /http|api|\/|secret|token|key|admin|firebase|graphql|auth/.test(s));
  interesting.slice(0, 40).forEach(s => console.log(`  ${s.substring(0, 150)}`));
  if (interesting.length > 40) console.log(`  ... and ${interesting.length - 40} more`);

  console.log(`\n[10] Anti-Debugger Detection`);
  console.log(`  ${'-'.repeat(50)}`);
  const ad = detectAntiDebug(code);
  if (ad.length > 0) {
    const seen = new Set();
    ad.forEach(a => { const k = a.type; if (!seen.has(k)) { seen.add(k); console.log(`  [!] ${a.type}`); } });
    console.log(`  Total anti-debug patterns: ${ad.length}`);
  } else { console.log(`  No anti-debug patterns detected`); }

  console.log(`\n[11] Self-Defending / Integrity Checks`);
  console.log(`  ${'-'.repeat(50)}`);
  const sd = detectSelfDefending(code);
  if (sd.length > 0) {
    const seen = new Set();
    sd.forEach(s => { const k = s.type; if (!seen.has(k)) { seen.add(k); console.log(`  [!] ${s.type}`); } });
    console.log(`  Total integrity check patterns: ${sd.length}`);
  } else { console.log(`  No self-defending patterns detected`); }

  console.log(`\n[12] Eval String Extraction & Recursive Deobfuscation`);
  console.log(`  ${'-'.repeat(50)}`);
  const ev = extractEvalStrings(code);
  if (ev.length > 0) {
    ev.slice(0, 10).forEach(e => {
      console.log(`  [${e.type}] (${e.length} chars)`);
      if (e.decoded) console.log(`    Decoded: ${e.decoded.substring(0, 150)}`);
      else console.log(`    Raw: ${e.raw.substring(0, 100)}`);
    });
    if (ev.length > 10) console.log(`  ... and ${ev.length - 10} more`);
  } else { console.log(`  No eval-like string calls detected`); }

  console.log(`\n[13] Nested / Multi-Layer Obfuscation Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  const nested = detectNestedObfuscation(code);
  if (nested.layers.length > 0) {
    nested.layers.forEach(l => console.log(`  ${l.type}: ${l.count} occurrence(s)`));
    console.log(`  Estimated layers: ${nested.estimate}`);
  } else { console.log(`  Single-layer obfuscation (no nesting detected)`); }

  console.log(`\n[14] Variable Naming Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  const varAnalysis = analyzeVariableNames(code);
  if (varAnalysis.length > 0) {
    varAnalysis.forEach(v => {
      if (v.examples) console.log(`  ${v.type}: ${v.count} (e.g. ${v.examples.slice(0, 5).join(', ')})`);
      else console.log(`  ${v.type}: ${v.count}`);
    });
  } else { console.log(`  Normal variable naming patterns`); }

  console.log(`\n[15] Control Flow Flattening Detection`);
  console.log(`  ${'-'.repeat(50)}`);
  const cff = detectControlFlowFlattening(code);
  if (cff.length > 0) {
    cff.forEach(c => console.log(`  [!] ${c.type}: ${c.match.substring(0, 60)}`));
  } else { console.log(`  No control flow flattening detected`); }

  console.log(`\n[16] Hidden Payload Extraction`);
  console.log(`  ${'-'.repeat(50)}`);
  const hp = extractHiddenPayloads(code);
  if (hp.length > 0) {
    hp.forEach(h => console.log(`  ${h.label}: ${h.count} occurrence(s)`));
  } else { console.log(`  No hidden payload patterns detected`); }

  console.log(`\n[17] Unicode Homoglyph / Normalization Attack Check`);
  console.log(`  ${'-'.repeat(50)}`);
  const ua = detectUnicodeAttacks(code);
  if (ua.length > 0) {
    ua.forEach(u => {
      console.log(`  [!] ${u.label}: ${u.count} occurrence(s)`);
      if (u.sample) console.log(`    Context: ${u.sample.substring(0, 80)}`);
    });
  } else { console.log(`  No unicode attack patterns detected`); }

  console.log(`\n[18] Obfuscation Probability Scoring (by section)`);
  console.log(`  ${'-'.repeat(50)}`);
  const sections = scoreObfuscationSections(code);
  if (sections.length > 0) {
    console.log(`  Top obfuscated sections:`);
    sections.slice(0, 10).forEach(s => console.log(`    Line ${s.line}: score=${s.score} [${s.severity}] (${s.reasons.join(', ')})`));
  } else { console.log(`  No high-obfuscation sections detected`); }

  console.log(`\n[19] Automated String Deobfuscation Pipeline`);
  console.log(`  ${'-'.repeat(50)}`);
  const pipe = autoDeobfuscate(code);
  if (pipe.transforms > 0) {
    console.log(`  Transforms applied: ${pipe.transforms}`);
    pipe.steps.slice(0, 10).forEach(s => console.log(`    ${s}`));
    if (pipe.steps.length > 10) console.log(`    ... and ${pipe.steps.length - 10} more`);
    const ratio = ((1 - pipe.decoded.length / code.length) * 100).toFixed(1);
    console.log(`  Size reduction: ${code.length} -> ${pipe.decoded.length} chars (${ratio}%)`);
    const newFindings = [];
    const urlRe = /https?:\/\/[^\s"'`)]+/g;
    let m;
    while ((m = urlRe.exec(pipe.decoded)) !== null) {
      if (!code.includes(m[0])) newFindings.push(m[0]);
    }
    if (newFindings.length > 0) {
      console.log(`  [!] Newly deobfuscated URLs/endpoints:`);
      newFindings.slice(0, 15).forEach(u => console.log(`    ${u.substring(0, 120)}`));
    }
  } else { console.log(`  No automatic deobfuscation needed (no encoded strings)`); }

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Scan complete: ${filename}`);
  console.log(`${'='.repeat(70)}\n`);
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log(`Usage: node deobfuscate.js <input.js>`);
  console.log(`       node deobfuscate.js <directory>`);
  process.exit(1);
}

const inputPath = args[0];
if (fs.statSync(inputPath).isDirectory()) {
  const files = fs.readdirSync(inputPath).filter(f => f.endsWith('.js'));
  files.forEach(f => scan(path.join(inputPath, f)));
} else {
  scan(inputPath);
}
