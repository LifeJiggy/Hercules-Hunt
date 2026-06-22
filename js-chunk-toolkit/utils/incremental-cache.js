const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CACHE_DIR = path.join(__dirname, '..', 'output', '.cache');

function ensureCacheDir() { fs.mkdirSync(CACHE_DIR, { recursive: true }); }

function fileHash(filePath) {
  try {
    const stat = fs.statSync(filePath);
    const firstBytes = fs.readFileSync(filePath, { encoding: 'utf-8', flag: 'r' }).substring(0, 4096);
    return crypto.createHash('md5').update(`${stat.size}:${stat.mtimeMs}:${firstBytes.length}`).digest('hex').substring(0, 16);
  } catch { return null; }
}

function getCached(filePath) {
  ensureCacheDir();
  const hash = fileHash(filePath);
  if (!hash) return null;
  const cacheFile = path.join(CACHE_DIR, `${hash}.json`);
  try {
    if (fs.existsSync(cacheFile)) return JSON.parse(fs.readFileSync(cacheFile, 'utf-8'));
  } catch {}
  return null;
}

function setCached(filePath, data) {
  ensureCacheDir();
  const hash = fileHash(filePath);
  if (!hash) return;
  const cacheFile = path.join(CACHE_DIR, `${hash}.json`);
  fs.writeFileSync(cacheFile, JSON.stringify(data));
}

function clearCache() {
  try {
    if (fs.existsSync(CACHE_DIR)) {
      const files = fs.readdirSync(CACHE_DIR);
      files.forEach(f => fs.unlinkSync(path.join(CACHE_DIR, f)));
      return { cleared: files.length };
    }
  } catch {}
  return { cleared: 0 };
}

function processWithCache(files, processor) {
  const results = [];
  let cached = 0;
  let processed = 0;

  for (const file of files) {
    const cachedData = getCached(file);
    if (cachedData) {
      results.push({ file, ...cachedData, cached: true });
      cached++;
    } else {
      const result = processor(file);
      if (result) {
        setCached(file, result);
        results.push({ file, ...result, cached: false });
      }
      processed++;
    }
  }

  return { results, cached, processed };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.log('Usage: node incremental-cache.js <directory> [--clear]');
    process.exit(1);
  }

  if (args.includes('--clear')) {
    const result = clearCache();
    console.log(`\n[OK] Cleared ${result.cleared} cache entries\n`);
    process.exit(0);
  }

  const dir = path.resolve(args[0]);
  const jsFiles = fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => path.join(dir, f));

  const start = Date.now();
  const result = processWithCache(jsFiles, (file) => {
    const content = fs.readFileSync(file, 'utf-8');
    const findings = [];
    const awsRe = /AKIA[0-9A-Z]{16}/g; let m;
    while ((m = awsRe.exec(content)) !== null) findings.push({ value: m[0].substring(0, 40) });
    return { totalSize: content.length, findings, findingCount: findings.length, hash: crypto.createHash('md5').update(content).digest('hex').substring(0, 16) };
  });

  const elapsed = ((Date.now() - start) / 1000).toFixed(2);
  console.log(`\n========================================`);
  console.log(`  Incremental Analysis Cache`);
  console.log(`========================================`);
  console.log(`  Files:     ${jsFiles.length}`);
  console.log(`  Cached:    ${result.cached}`);
  console.log(`  Processed: ${result.processed}`);
  console.log(`  Time:      ${elapsed}s`);
  console.log(`  Cache dir: ${CACHE_DIR}\n`);
}

module.exports = { getCached, setCached, clearCache, processWithCache };
