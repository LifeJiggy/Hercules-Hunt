const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;
if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node call-graph-builder.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

function buildCallGraph(inputCode) {
  const functions = [];
  const funcRe = /(?:function\s+(\w+)\s*\(|(\w+)\s*=\s*function\s*\()/g;
  let m;
  while ((m = funcRe.exec(inputCode)) !== null) {
    const name = m[1] || m[2];
    functions.push({ name, calls: [], calledBy: [], pos: m.index });
  }

  for (const fn of functions) {
    const start = fn.pos;
    const end = functions.reduce((next, f) => f.pos > start && (!next || f.pos < next) ? f.pos : next, inputCode.length);
    const body = inputCode.substring(start, end);
    const callRe = /\b(\w+)\s*\(/g;
    let cm;
    while ((cm = callRe.exec(body)) !== null) {
      const called = functions.find(f => f.name === cm[1] && f.name !== fn.name);
      if (called) {
        fn.calls.push(called.name);
        called.calledBy.push(fn.name);
      }
    }
  }

  const entryPoints = functions.filter(f => f.calledBy.length === 0);
  const leaves = functions.filter(f => f.calls.length === 0 && f.calledBy.length > 0);

  return { functions, entryPoints, leaves };
}

if (isCLI) {
  const graph = buildCallGraph(code);
  console.log(`\n========================================`);
  console.log(`  Function Call Graph`);
  console.log(`========================================`);
  console.log(`  Functions:     ${graph.functions.length}`);
  console.log(`  Entry points:  ${graph.entryPoints.length}`);
  console.log(`  Leaf nodes:    ${graph.leaves.length}`);
  if (graph.entryPoints.length > 0) {
    console.log('\n  Entry points:');
    graph.entryPoints.forEach(f => console.log(`    ${f.name} → calls ${f.calls.length} function(s)`));
  }
  if (graph.leaves.length > 0) {
    console.log('\n  Leaves:');
    const top = graph.leaves.sort((a, b) => b.calledBy.length - a.calledBy.length).slice(0, 10);
    top.forEach(f => console.log(`    ${f.name} (called by ${f.calledBy.length})`));
  }
  const dot = ['digraph CallGraph {'];
  for (const fn of graph.functions) {
    for (const callee of fn.calls) dot.push(`  "${fn.name}" -> "${callee}";`);
  }
  dot.push('}');
  if (dot.length > 2) console.log(`\n  DOT graph: ${dot.length - 2} edges`);
  console.log('');
}

module.exports = { buildCallGraph };
