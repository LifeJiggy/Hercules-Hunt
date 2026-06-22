const fs = require('fs');
const path = require('path');
const vm = require('vm');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let inputFile, outputFile, code;

if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node string-array-decoder.js <file.js> [--output decoded.js]'); process.exit(1); }
  inputFile = args[0];
  const outFlag = args.indexOf('--output');
  outputFile = outFlag > -1 && args[outFlag + 1] ? args[outFlag + 1] : null;
  const loaded = harden.safeLoadFile(inputFile);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

function decodeStringArrays(inputCode) {
  let code = inputCode;
  const origLen = code.length;
let decodedCount = 0;
let arraysFound = 0;

const STRING_ARRAY_PATTERNS = [
  {
    name: 'var = [string,...] simple',
    re: /(?:var|let|const)\s+(\w+)\s*=\s*\[([^\]]{20,})\]/g,
    extract: (m) => {
      try {
        const arr = JSON.parse(`[${m[2]}]`);
        return { name: m[1], array: arr };
      } catch { return null; }
    }
  },
  {
    name: 'var = [string,...] multi-line',
    re: /(?:var|let|const)\s+(\w+)\s*=\s*\[([\s\S]{20,}?)\];/g,
    extract: (m) => {
      try {
        const cleaned = m[2].replace(/\n\s*/g, '');
        const arr = JSON.parse(`[${cleaned}]`);
        return { name: m[1], array: arr };
      } catch { return null; }
    }
  }
];

function findDecoders() {
  const results = [];
  const decoderRe = /function\s+(\w+)\s*\((\w+)(?:,\s*\w+)?\)\s*\{[\s\S]{20,500}?\}/g;
  let m;
  while ((m = decoderRe.exec(code)) !== null) {
    const body = m[0];
    const arrMatch = body.match(/(\w+)\s*\[\s*\w+\s*[-+*/%]\s*\d+\s*\]|(\w+)\s*\[\s*\w+\s*\]/);
    if (arrMatch) {
      results.push({ name: m[1], param: m[2], arrName: arrMatch[1] || arrMatch[2], body: body.substring(0, 200) });
    }
  }
  return results;
}

function findEncoderFunctions() {
  const results = [];
  const shiftRe = /function\s+(\w+)\s*\([\s\S]{0,100}?\)\s*\{[\s\S]{0,500}?(\w+)\.(?:shift|pop|splice|reverse|sort)\(/g;
  let m;
  while ((m = shiftRe.exec(code)) !== null) {
    results.push({ name: m[1], arrName: m[2], operation: m[0].match(/\.(shift|pop|splice|reverse|sort)\(/)[1] });
  }
  return results;
}

function emulateDecoder(code, arrayName, decoderName) {
  try {
    const extractCode = `
      var ${arrayName} = null;
      ${code}
      if (typeof ${decoderName} === 'function' && Array.isArray(${arrayName})) {
        var result = {};
        for (var i = 0; i < ${arrayName}.length; i++) {
          try { result[i] = ${decoderName}(i); } catch(e) { result[i] = null; }
        }
        JSON.stringify(result);
      }
    `;
    const script = new vm.Script(extractCode);
    const result = script.runInNewContext({}, { timeout: 200, breakOnSigint: true });
    return result ? JSON.parse(result) : null;
  } catch { return null; }
}

function decodeAllReferences(name, decoded) {
  let changed = false;
  const refRe = new RegExp(`${name}\\s*\\[\\s*(\\d+)\\s*\\]`, 'g');
  let m;
  const replacements = [];
  while ((m = refRe.exec(code)) !== null) {
    const idx = parseInt(m[1]);
    if (decoded[idx] !== undefined && decoded[idx] !== null) {
      const val = typeof decoded[idx] === 'string' ? JSON.stringify(decoded[idx]) : String(decoded[idx]);
      replacements.push({ index: m.index, origLen: m[0].length, val });
    }
  }
  for (let i = replacements.length - 1; i >= 0; i--) {
    const r = replacements[i];
    code = code.substring(0, r.index) + r.val + code.substring(r.index + r.origLen);
    decodedCount++;
    changed = true;
  }
  return changed;
}

const decoders = findDecoders();
const encoders = findEncoderFunctions();

for (const pat of STRING_ARRAY_PATTERNS) {
  let m;
  while ((m = pat.re.exec(code)) !== null) {
    const extracted = pat.extract(m);
    if (extracted && extracted.array && extracted.array.length > 2) {
      arraysFound++;
      const allStrings = extracted.array.every(s => typeof s === 'string');
      if (!allStrings) continue;
      for (const dec of decoders) {
        if (dec.arrName === extracted.name) {
          const decoded = emulateDecoder(code, extracted.name, dec.name);
          if (decoded) { decodeAllReferences(extracted.name, decoded); }
        }
      }
      for (const enc of encoders) {
        if (enc.arrName === extracted.name) {
          const decoded = emulateDecoder(code, extracted.name, enc.name);
          if (decoded) { decodeAllReferences(extracted.name, decoded); }
        }
      }
    }
  
}
  return { decoders, encoders, arrays: arraysFound, decoded: decodedCount, output: code, inputSize: origLen };
}
}

if (isCLI) {
  const result = decodeStringArrays(code);
  const ratio = result.inputSize > 0 ? ((1 - result.output.length / result.inputSize) * 100).toFixed(2) : '0.00';
  console.log(`\n========================================`);
  console.log(`  String Array Decoder`);
  console.log(`========================================`);
  console.log(`  Array literals found:  ${result.arrays}`);
  console.log(`  Decoder functions:     ${result.decoders.length}`);
  console.log(`  Encoder functions:     ${result.encoders.length}`);
  console.log(`  References decoded:    ${result.decoded}`);
  console.log(`  Input size:            ${result.inputSize} chars`);
  console.log(`  Output size:           ${result.output.length} chars`);
  console.log(`  Reduction:             ${ratio}%`);
  console.log('');
  if (result.decoders.length > 0) {
    console.log('  Decoder functions:');
    result.decoders.slice(0, 5).forEach(d => console.log(`    ${d.name}(${d.param}) → array "${d.arrName}"`));
  }
  if (result.encoders.length > 0) {
    console.log('  Encoder operations:');
    result.encoders.slice(0, 5).forEach(e => console.log(`    ${e.name} → ${e.arrName}.${e.operation}()`));
  }
  console.log('');
  if (outputFile) {
    fs.mkdirSync(path.dirname(path.resolve(outputFile)), { recursive: true });
    fs.writeFileSync(outputFile, result.output, 'utf-8');
    console.log(`[OK] Decoded output written to ${path.resolve(outputFile)}\n`);
  }
}

module.exports = { decodeStringArrays };
