const fs = require('fs');
const path = require('path');

const DEFAULT_BUDGET = 512 * 1024 * 1024;
const FLUSH_DIR = path.join(__dirname, '..', 'output', 'memory-flush');

class MemoryBudgetTracker {
  constructor(options = {}) {
    this.maxHeap = options.maxHeap || DEFAULT_BUDGET;
    this.flushDir = options.flushDir || FLUSH_DIR;
    this.totalAllocated = 0;
    this.flushCount = 0;
    fs.mkdirSync(this.flushDir, { recursive: true });
  }

  allocate(size) {
    this.totalAllocated += size;
    if (this.totalAllocated > this.maxHeap) {
      this.flush();
      return false;
    }
    return true;
  }

  release(size) {
    this.totalAllocated = Math.max(0, this.totalAllocated - size);
  }

  flush() {
    this.flushCount++;
    const usage = process.memoryUsage();
    const flushFile = path.join(this.flushDir, `flush-${Date.now()}-${this.flushCount}.json`);
    fs.writeFileSync(flushFile, JSON.stringify({
      timestamp: new Date().toISOString(),
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      rss: usage.rss,
      external: usage.external,
      flushNumber: this.flushCount
    }));
    this.totalAllocated = 0;
    if (global.gc) global.gc();
  }

  getStats() {
    const usage = process.memoryUsage();
    return {
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      maxHeap: this.maxHeap,
      percentUsed: ((usage.heapUsed / this.maxHeap) * 100).toFixed(1),
      flushCount: this.flushCount,
      totalAllocated: this.totalAllocated
    };
  }
}

function processWithBudget(filePath, budget) {
  const content = fs.readFileSync(filePath, 'utf-8');
  if (!budget.allocate(content.length)) {
    console.log(`  [FLUSH] Budget exceeded at ${(content.length / 1024 / 1024).toFixed(1)}MB`);
    return null;
  }

  const findings = [];
  const awsRe = /AKIA[0-9A-Z]{16}/g; let m;
  while ((m = awsRe.exec(content)) !== null) findings.push(m[0]);

  budget.release(content.length);
  return findings;
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const budgetFlag = args.indexOf('--max-heap');
  const maxHeap = budgetFlag > -1 ? parseInt(args[budgetFlag + 1]) * 1024 * 1024 : DEFAULT_BUDGET;

  const tracker = new MemoryBudgetTracker({ maxHeap });
  const stats = tracker.getStats();
  console.log(`\n========================================`);
  console.log(`  Memory-Budgeted Processing`);
  console.log(`========================================`);
  console.log(`  Max heap:  ${(maxHeap / 1024 / 1024).toFixed(0)}MB`);
  console.log(`  Current:   ${stats.heapUsed} bytes (${stats.percentUsed}%)`);
  console.log(`  Flush dir: ${FLUSH_DIR}`);

  if (args[0] && fs.existsSync(args[0])) {
    const stat = fs.statSync(args[0]);
    console.log(`  File:      ${path.basename(args[0])} (${(stat.size / 1024 / 1024).toFixed(1)}MB)`);
  }

  if (args.includes('--simulate-large') && args[0]) {
    const filePath = path.resolve(args[0]);
    const result = processWithBudget(filePath, tracker);
    console.log(`\n  Findings: ${result ? result.length : 'FLUSHED'}`);
    console.log(`  Flushes:  ${tracker.flushCount}`);
    console.log(`  Stats:    ${JSON.stringify(tracker.getStats())}`);
  }

  console.log('');
}

module.exports = { MemoryBudgetTracker, processWithBudget };
