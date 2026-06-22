const fs = require('fs');
const path = require('path');
const { Worker } = require('worker_threads');

function createWorkerScript() {
  return `
const { parentPort } = require('worker_threads');
parentPort.on('message', ({ filePath, code }) => {
  try {
    const findings = [];
    const awsRe = /AKIA[0-9A-Z]{16}/g; let m;
    while ((m = awsRe.exec(code)) !== null) findings.push({ type: 'AWS Key', value: m[0], line: code.substring(0, m.index).split('\\n').length });
    const urlRe = /https?:\\/\\/[^\\s"')\`]{20,}/g;
    while ((m = urlRe.exec(code)) !== null) findings.push({ type: 'URL', value: m[0].substring(0, 100) });
    const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}/g;
    while ((m = jwtRe.exec(code)) !== null) findings.push({ type: 'JWT', value: m[0].substring(0, 60) });
    parentPort.postMessage({ filePath, findings });
  } catch (e) { parentPort.postMessage({ filePath, error: e.message }); }
});
  `;
}

function scanFiles(files, options = {}) {
  return new Promise((resolve) => {
    const maxWorkers = options.workers || Math.min(4, require('os').cpus().length);
    let completed = 0;
    const allFindings = [];
    let idx = 0;

    function startWorker() {
      if (idx >= files.length) { return; }
      const currentIdx = idx++;
      const filePath = files[currentIdx];
      const worker = new Worker(createWorkerScript(), { eval: true });
      worker.on('message', ({ filePath: fp, findings, error }) => {
        if (error) console.error(`  Worker error (${path.basename(fp)}): ${error}`);
        else allFindings.push(...(findings || []));
        completed++;
        worker.terminate();
        if (completed >= files.length) resolve(allFindings);
        else startWorker();
      });
      try {
        const code = fs.readFileSync(filePath, 'utf-8');
        worker.postMessage({ filePath, code });
      } catch (e) {
        completed++;
        worker.terminate();
        if (completed >= files.length) resolve(allFindings);
        else startWorker();
      }
    }

    if (files.length === 0) resolve([]);
    for (let i = 0; i < Math.min(maxWorkers, files.length); i++) { startWorker(); }
  });
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Usage: node worker-pool.js <directory> [--workers 4]');
    process.exit(1);
  }

  const dir = path.resolve(args[0]);
  const workersFlag = args.indexOf('--workers');
  const maxWorkers = workersFlag > -1 ? parseInt(args[workersFlag + 1]) || 4 : 4;

  const jsFiles = fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => path.join(dir, f));
  console.log(`\n========================================`);
  console.log(`  Worker Thread Pool`);
  console.log(`========================================`);
  console.log(`  Workers:  ${maxWorkers}`);
  console.log(`  Files:    ${jsFiles.length}`);
  console.log('');

  const start = Date.now();
  scanFiles(jsFiles, { workers: maxWorkers }).then(findings => {
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    console.log(`  Findings: ${findings.length}`);
    const byType = {};
    findings.forEach(f => { byType[f.type] = (byType[f.type] || 0) + 1; });
    Object.entries(byType).slice(0, 10).forEach(([t, c]) => console.log(`    ${t}: ${c}`));
    console.log(`\n  Time: ${elapsed}s (${(jsFiles.length / elapsed).toFixed(1)} files/s)\n`);
  });
}

module.exports = { scanFiles };
