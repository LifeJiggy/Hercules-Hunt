const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const args = process.argv.slice(2);
if (args.length < 1) {
  console.log('Usage: node watch-mode.js <directory> [--command "node deobfuscate.js <file>"]');
  console.log('  Watches directory for new/changed JS files, auto-runs command.');
  process.exit(1);
}

const watchDir = path.resolve(args[0]);
const cmdFlag = args.indexOf('--command');
const command = cmdFlag > -1 ? args.slice(cmdFlag + 1).join(' ') : null;

if (!fs.existsSync(watchDir)) {
  console.error(`Directory not found: ${watchDir}`);
  process.exit(1);
}

console.log(`\n========================================`);
console.log(`  Watch Mode — ${watchDir}`);
console.log(`========================================`);
console.log('  Watching for .js file changes...');
console.log('  Press Ctrl+C to stop.\n');

const debounceTimers = {};

function processFile(filePath) {
  const relative = path.relative(watchDir, filePath);
  const timestamp = new Date().toISOString().substring(11, 19);

  if (command) {
    const cmd = command.replace('<file>', `"${filePath}"`);
    try {
      console.log(`[${timestamp}] Processing ${relative}...`);
      const output = execSync(cmd, { encoding: 'utf-8', timeout: 30000, cwd: path.join(__dirname, '..') });
      const lines = output.split('\n').filter(l => l.includes('[1]') || l.includes('CRITICAL') || l.includes('secret') || l.includes('Found'));
      lines.forEach(l => console.log(`  ${l.trim()}`));
    } catch (e) {
      console.error(`  Error: ${e.message.substring(0, 100)}`);
    }
  } else {
    console.log(`[${timestamp}] Changed: ${relative}`);
  }
}

fs.watch(watchDir, { recursive: true }, (eventType, filename) => {
  if (!filename || !filename.endsWith('.js')) return;
  const filePath = path.join(watchDir, filename);
  if (!fs.existsSync(filePath)) return;

  if (debounceTimers[filename]) clearTimeout(debounceTimers[filename]);
  debounceTimers[filename] = setTimeout(() => {
    delete debounceTimers[filename];
    processFile(filePath);
  }, 500);
});

console.log(`\n  Watching ${watchDir}...\n`);
