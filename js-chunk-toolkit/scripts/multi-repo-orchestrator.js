const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log('Usage: node multi-repo-orchestrator.js <targets.json|target1,target2,...>');
  console.log('  targets.json: [{ "url": "https://target.com", "name": "target1", "pipelines": ["deobfuscate","scan"] }]');
  process.exit(1);
}

const ROOT_DIR = path.join(__dirname, '..', 'output', 'multi-repo');

function ensureDir(d) { fs.mkdirSync(d, { recursive: true }); }

let targets;
if (args[0].endsWith('.json')) {
  targets = JSON.parse(fs.readFileSync(args[0], 'utf-8'));
  if (!Array.isArray(targets)) targets = [targets];
} else {
  targets = args[0].split(',').map((t, i) => ({ url: t.trim(), name: `target-${i+1}` }));
}

const pipelines = args.includes('--no-download') ? [] : ['download'];
if (!args.includes('--scan-only')) {
  pipelines.push('deobfuscate', 'analyze', 'report');
}

console.log(`\n========================================`);
console.log(`  Multi-Repo Orchestrator`);
console.log(`========================================`);
console.log(`  Targets: ${targets.length}`);
console.log(`  Pipelines: ${pipelines.join(', ') || 'none'}`);
console.log('');

const results = [];

for (const target of targets) {
  const name = target.name || new URL(target.url).hostname;
  const outDir = path.join(ROOT_DIR, name);
  ensureDir(outDir);

  console.log(`\n  [${name}] Starting...`);

  if (pipelines.includes('deobfuscate')) {
    const script = path.join(__dirname, 'deobfuscate.js');
    if (fs.existsSync(script)) {
      try {
        const jsFiles = fs.readdirSync(outDir).filter(f => f.endsWith('.js'));
        for (const js of jsFiles.slice(0, 5)) {
          const jsPath = path.join(outDir, js);
          const output = execSync(`node "${script}" "${jsPath}"`, { encoding: 'utf-8', timeout: 60000, cwd: path.join(__dirname, '..') });
          const reportPath = path.join(outDir, `${js}.report.txt`);
          fs.writeFileSync(reportPath, output);
        }
        console.log(`    Deobfuscation complete`);
      } catch (e) { console.error(`    Error: ${e.message.substring(0, 80)}`); }
    }
  }

  if (pipelines.includes('download')) {
    const downloader = path.join(__dirname, '..', 'utils', 'download-js.ps1');
    if (fs.existsSync(downloader)) {
      try {
        execSync(`powershell -File "${downloader}" -TargetUrl "${target.url}" -OutputDir "${outDir}"`, { timeout: 120000 });
        console.log(`    Download complete`);
      } catch (e) { console.error(`    Download error: ${e.message.substring(0, 80)}`); }
    }
  }

  results.push({ name, url: target.url, outDir, status: 'done' });
}

const summaryPath = path.join(ROOT_DIR, 'summary.json');
const summary = {
  date: new Date().toISOString(),
  targets: results.length,
  pipelines,
  results
};
fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

console.log(`\n  Summary written to ${summaryPath}`);
console.log(`  Targets processed: ${results.length}`);
console.log(`  Output: ${ROOT_DIR}\n`);
