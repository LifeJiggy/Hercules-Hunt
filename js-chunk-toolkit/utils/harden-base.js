const fs = require('fs');
const path = require('path');

const MAX_FILE_SIZE = 50 * 1024 * 1024;
const REGEX_TIMEOUT_MS = 5000;
const BINARY_PATTERNS = [0x00, 0xFF, 0x00, 0x00].map(b => Buffer.from([b]));

function isBinary(buf) {
  const sample = buf.slice(0, Math.min(buf.length, 8192));
  let nullCount = 0;
  for (let i = 0; i < sample.length; i++) {
    if (sample[i] === 0) nullCount++;
    if (nullCount > sample.length * 0.01) return true;
  }
  return false;
}

function safeLoadFile(filePath) {
  try {
    if (!filePath || !fs.existsSync(filePath)) return { ok: false, error: 'File not found', content: '' };
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) return { ok: false, error: 'Not a file', content: '' };
    if (stat.size > MAX_FILE_SIZE) return { ok: false, error: `File too large (${(stat.size / 1024 / 1024).toFixed(1)}MB > 50MB limit)`, content: '' };
    if (stat.size === 0) return { ok: true, content: '', note: 'empty' };
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(Math.min(stat.size, 8192));
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);
    if (isBinary(buf)) return { ok: false, error: 'Binary file detected', content: '' };
    const content = fs.readFileSync(filePath, { encoding: 'utf-8', flag: 'r' });
    if (content.length === 0) return { ok: true, content: '', note: 'empty' };
    const normalized = content.replace(/\r\n/g, '\n');
    return { ok: true, content: normalized, size: normalized.length };
  } catch (e) {
    return { ok: false, error: e.message, content: '' };
  }
}

function safeLoadFiles(dir, ext = ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx']) {
  if (!dir || !fs.existsSync(dir)) return { ok: false, error: 'Path not found', files: [] };
  const results = [];
  const errors = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d); }
    catch (e) { errors.push(`Cannot read ${d}: ${e.message}`); return; }
    for (const f of entries) {
      const fp = path.join(d, f);
      let stat;
      try { stat = fs.statSync(fp); }
      catch (e) { errors.push(`Cannot stat ${fp}: ${e.message}`); continue; }
      if (stat.isDirectory()) { walk(fp); continue; }
      if (stat.size === 0) { continue; }
      if (stat.size > MAX_FILE_SIZE) { results.push({ name: path.relative(dir, fp), filePath: fp, content: '', note: 'skipped: too large' }); continue; }
      if (!ext.some(e => f.toLowerCase().endsWith(e))) continue;
      const loaded = safeLoadFile(fp);
      if (loaded.ok) {
        results.push({ name: path.relative(dir, fp), filePath: fp, content: loaded.content, note: loaded.note || '' });
      } else {
        errors.push(`${fp}: ${loaded.error}`);
      }
    }
  }
  walk(dir);
  return { ok: true, files: results, errors };
}

function safeLoadConfig(configPath) {
  try {
    if (!configPath || !fs.existsSync(configPath)) return { ok: false, error: 'Config not found', data: null };
    const raw = fs.readFileSync(configPath, 'utf-8');
    const data = JSON.parse(raw);
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: `Config parse error: ${e.message}`, data: null };
  }
}

function safeJsonStringify(obj, indent = 2) {
  const seen = new WeakSet();
  try {
    return JSON.stringify(obj, (key, val) => {
      if (typeof val === 'object' && val !== null) {
        if (seen.has(val)) return '[Circular]';
        seen.add(val);
      }
      if (typeof val === 'function') return '[Function]';
      if (typeof val === 'symbol') return val.toString();
      if (typeof val === 'bigint') return val.toString();
      if (val instanceof Error) return { message: val.message, stack: val.stack?.substring(0, 500) };
      return val;
    }, indent);
  } catch (e) {
    return JSON.stringify({ error: 'Stringify failed', message: e.message });
  }
}

function batchProcess(items, fn, batchSize = 50) {
  const results = [];
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    for (const item of batch) {
      try { results.push(fn(item)); }
      catch (e) { results.push({ error: e.message, item }); }
    }
  }
  return results;
}

class ProgressTracker {
  constructor(total, label = 'Processing') {
    this.total = total;
    this.label = label;
    this.current = 0;
    this.startTime = Date.now();
    this.lastLog = 0;
  }

  tick(n = 1) {
    this.current += n;
    const elapsed = Date.now() - this.startTime;
    if (elapsed - this.lastLog < 2000 && this.current < this.total) return;
    this.lastLog = elapsed;
    const pct = this.total > 0 ? Math.round(this.current / this.total * 100) : 0;
    const rate = this.current > 0 ? Math.round(this.current / (elapsed / 1000)) : 0;
    const eta = rate > 0 ? Math.round((this.total - this.current) / rate) : 0;
    const etaStr = eta > 0 ? `ETA ${eta}s` : 'done';
    process.stderr.write(`\r  ${this.label}: ${this.current}/${this.total} (${pct}%) ${rate}/s ${etaStr}  `);
    if (this.current >= this.total) process.stderr.write('\n');
  }
}

function withTimeout(fn, timeoutMs = REGEX_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out after ${timeoutMs}ms`)), timeoutMs);
    try {
      const result = fn();
      clearTimeout(timer);
      resolve(result);
    } catch (e) {
      clearTimeout(timer);
      reject(e);
    }
  });
}

function safeRegexTest(regex, str) {
  if (!str) return false;
  try {
    const result = regex.test(str);
    regex.lastIndex = 0;
    return result;
  } catch (e) {
    return false;
  }
}

function safeRegexExec(regex, str) {
  if (!str) return null;
  try {
    const result = regex.exec(str);
    return result;
  } catch (e) {
    return null;
  }
}

function safeRegexMatchAll(str, regex) {
  if (!str) return [];
  const results = [];
  try {
    let m;
    const re = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
    let iterations = 0;
    while ((m = re.exec(str)) !== null && iterations < 100000) {
      results.push(m);
      iterations++;
      if (iterations > 50000) break;
    }
    return results;
  } catch (e) {
    return results;
  }
}

function detectEncoding(content) {
  if (!content || content.length === 0) return 'empty';
  if (content.startsWith('\uFEFF')) return 'utf-8-bom';
  if (content.startsWith('\uFFFE')) return 'utf-16-le';
  if (content.startsWith('\u0000')) return 'binary';
  if (/^[\x00-\x08\x0B\x0C\x0E-\x1F]*$/.test(content.substring(0, 100))) return 'binary';
  const hasHighChars = [...content.substring(0, 1000)].some(c => c.charCodeAt(0) > 127);
  return hasHighChars ? 'utf-8' : 'ascii';
}

function validatePath(inputPath) {
  if (!inputPath || typeof inputPath !== 'string') return { ok: false, error: 'Invalid path' };
  if (inputPath.length > 4096) return { ok: false, error: 'Path too long' };
  if (/[<>"|?*]/.test(inputPath)) return { ok: false, error: 'Path contains invalid characters' };
  try {
    const resolved = path.resolve(inputPath);
    return { ok: true, path: resolved };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function analyzeStrings(content) {
  const results = {};
  const hexStrings = content.match(/(?:\\x[0-9a-fA-F]{2}){4,}/g);
  if (hexStrings) results.hexStrings = hexStrings.slice(0, 20);

  const unicodeEscapes = content.match(/(?:\\u[0-9a-fA-F]{4}){2,}/g);
  if (unicodeEscapes) results.unicodeEscapes = unicodeEscapes.slice(0, 20);

  const base64Strings = content.match(/[A-Za-z0-9+/]{40,}(?:[A-Za-z0-9+/]{4})*/g);
  if (base64Strings) results.base64Candidates = base64Strings.slice(0, 20);

  const numberStrings = content.match(/["'`]\d{8,}["'`]/g);
  if (numberStrings) results.largeNumbers = numberStrings.slice(0, 10);

  results.entropy = estimateEntropy(content.substring(0, 10000));
  results.avgLineLen = content.length > 0 ? Math.round(content.length / Math.max(1, content.split('\n').length)) : 0;

  return results;
}

function estimateEntropy(str) {
  if (!str || str.length < 100) return 0;
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

function colorize(severity) {
  const colors = { CRITICAL: '\x1b[31m', HIGH: '\x1b[33m', MEDIUM: '\x1b[36m', LOW: '\x1b[32m', INFO: '\x1b[37m' };
  return (colors[severity] || '\x1b[37m') + severity + '\x1b[0m';
}

module.exports = {
  safeLoadFile, safeLoadFiles, safeLoadConfig, safeJsonStringify,
  batchProcess, ProgressTracker, withTimeout,
  safeRegexTest, safeRegexExec, safeRegexMatchAll,
  detectEncoding, validatePath, analyzeStrings, estimateEntropy,
  colorize, MAX_FILE_SIZE
};
