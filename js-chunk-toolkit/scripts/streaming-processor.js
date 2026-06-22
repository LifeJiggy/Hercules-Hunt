const fs = require('fs');
const path = require('path');
const { Transform } = require('stream');

class JSScannerStream extends Transform {
  constructor(options = {}) {
    super({ readableObjectMode: true });
    this.buffer = '';
    this.findings = [];
    this.patterns = options.patterns || [
      { name: 'AWS Key', re: /AKIA[0-9A-Z]{16}/g },
      { name: 'URL', re: /https?:\/\/[^\s"'`)]{20,}/g },
      { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
      { name: 'GitHub Token', re: /ghp_[A-Za-z0-9]{36}/g },
    ];
    this.maxChunkSize = options.maxChunkSize || 10 * 1024 * 1024;
  }

  _transform(chunk, encoding, callback) {
    this.buffer += chunk.toString();
    if (this.buffer.length > this.maxChunkSize) {
      processLineBased();
      this.buffer = '';
    }
    callback();
  }

  _flush(callback) {
    this.processLineBased();
    for (const f of this.findings) this.push(f);
    this.push(null);
    callback();
  }

  processLineBased() {
    const lines = this.buffer.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const p of this.patterns) {
        p.re.lastIndex = 0;
        let m;
        while ((m = p.re.exec(line)) !== null) {
          this.findings.push({ type: p.name, value: m[0], line: i + 1 });
        }
      }
    }
  }
}

function scanFileStream(filePath, options = {}) {
  return new Promise((resolve, reject) => {
    const findings = [];
    const stream = fs.createReadStream(filePath, { encoding: 'utf-8', highWaterMark: options.chunkSize || 65536 });
    const scanner = new JSScannerStream(options);

    stream.pipe(scanner)
      .on('data', (f) => findings.push(f))
      .on('end', () => resolve({ file: filePath, findings, total: findings.length }))
      .on('error', reject);
  });
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 1) {
    console.log('Usage: node streaming-processor.js <file.js>');
    process.exit(1);
  }

  const filePath = path.resolve(args[0]);
  const start = Date.now();

  scanFileStream(filePath).then(result => {
    const elapsed = ((Date.now() - start) / 1000).toFixed(2);
    console.log(`\n========================================`);
    console.log(`  Streaming File Processor`);
    console.log(`========================================`);
    console.log(`  File:     ${path.basename(filePath)}`);
    console.log(`  Findings: ${result.total}`);
    console.log(`  Time:     ${elapsed}s`);
    const byType = {};
    result.findings.forEach(f => { byType[f.type] = (byType[f.type] || 0) + 1; });
    Object.entries(byType).slice(0, 10).forEach(([t, c]) => console.log(`    ${t}: ${c}`));
    console.log('');
  }).catch(e => console.error(`Error: ${e.message}`));
}

module.exports = { JSScannerStream, scanFileStream };
