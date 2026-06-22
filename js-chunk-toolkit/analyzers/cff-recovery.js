const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const isCLI = require.main === module;
let code;

if (isCLI) {
  const args = process.argv.slice(2);
  if (args.length === 0) { console.log('Usage: node cff-recovery.js <file.js>'); process.exit(1); }
  const loaded = harden.safeLoadFile(args[0]);
  if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
  code = loaded.content;
}

const CFF_PATTERNS = [
  {
    name: 'while-true-switch dispatcher',
    re: /while\s*\(\s*!?\s*true\s*\)\s*\{[\s\S]{0,200}?switch\s*\(\s*(\w+)\s*\)/,
    extract: (m) => {
      const block = m[0];
      const dispatcherVar = m[1];
      const cases = block.match(/case\s+(\d+|0x[a-f0-9]+)\s*:[\s\S]{0,200}?break;/g);
      return { dispatcherVar, caseCount: cases ? cases.length : 0, block: block.substring(0, 300) };
    }
  },
  {
    name: 'for-switch with state var',
    re: /for\s*\(\s*(?:var|let|const)\s+(\w+)\s*=\s*\d+\s*;\s*\w+\s*!==\s*\w+\s*;\s*\)\s*\{[\s\S]{0,200}?switch\s*\(\s*\w+\s*\)/,
    extract: (m) => {
      const block = m[0];
      const cases = block.match(/case\s+(\d+|0x[a-f0-9]+)\s*:[\s\S]{0,200}?break;/g);
      return { dispatcherVar: m[1], caseCount: cases ? cases.length : 0, block: block.substring(0, 300) };
    }
  },
  {
    name: 'do-while-switch',
    re: /do\s*\{[\s\S]{0,200}?switch\s*\(\s*(\w+)\s*\)/,
    extract: (m) => {
      const block = m[0];
      const cases = block.match(/case\s+(\d+|0x[a-f0-9]+)\s*:[\s\S]{0,200}?break;/g);
      return { dispatcherVar: m[1], caseCount: cases ? cases.length : 0, block: block.substring(0, 300) };
    }
  }
];

function analyzeDispatcher(content) {
  const dispatchers = [];
  for (const pat of CFF_PATTERNS) {
    pat.re.lastIndex = 0;
    let m;
    while ((m = pat.re.exec(content)) !== null) {
      const info = pat.extract(m);
      if (info && info.caseCount > 3) {
        const line = content.substring(0, m.index).split('\n').length;
        const dispatcherUpdates = content.substring(m.index, m.index + 2000).match(new RegExp(`${info.dispatcherVar}\\s*=\\s*[^;]+`, 'g'));
        const stateCount = dispatcherUpdates ? new Set(dispatcherUpdates.map(s => s.match(/\d+/)?.[0]).filter(Boolean)).size : 0;

        dispatchers.push({
          pattern: pat.name,
          line,
          dispatcherVar: info.dispatcherVar,
          caseCount: info.caseCount,
          stateCount: stateCount || 'unknown',
          block: info.block
        });
      }
    }
  }
  return dispatchers;
}

function estimateCffComplexity(content) {
  const switchStatements = (content.match(/switch\s*\(/g) || []).length;
  const whileTrue = (content.match(/while\s*\(\s*!?\s*true\s*\)/g) || []).length;
  const breakStatements = (content.match(/\bbreak\s*;/g) || []).length;
  const defaultCases = (content.match(/\bdefault\s*:/g) || []).length;

  const cffScore = whileTrue * 10 + defaultCases * 5 + Math.floor(breakStatements / 5);
  return {
    switchStatements, whileTrue, breakStatements, defaultCases, cffScore,
    verdict: cffScore > 30 ? 'HEAVY_CFF' : cffScore > 15 ? 'MODERATE_CFF' : cffScore > 5 ? 'LIGHT_CFF' : 'NONE'
  };
}

function analyzeCFF(content) {
  const dispatchers = analyzeDispatcher(content);
  const complexity = estimateCffComplexity(content);
  return { dispatchers, ...complexity, score: complexity.cffScore, level: complexity.verdict };
}

if (isCLI) {
  const dispatchers = analyzeDispatcher(code);
  const complexity = estimateCffComplexity(code);

  console.log(`\n========================================`);
  console.log(`  Control Flow Flattening Recovery`);
  console.log(`========================================`);
  console.log(`  CFF dispatchers found:  ${dispatchers.length}`);
  console.log('');

  if (dispatchers.length === 0) {
    console.log(`  CFF complexity score:   ${complexity.cffScore} [${complexity.verdict}]`);
    if (complexity.verdict === 'NONE') { console.log('  No control flow flattening detected.\n'); process.exit(0); }
  }

  if (dispatchers.length > 0) {
    console.log('  Dispatchers:');
    dispatchers.forEach((d, i) => {
      console.log(`    #${i+1} ${d.pattern}`);
      console.log(`       Variable: ${d.dispatcherVar}`);
      console.log(`       Cases: ${d.caseCount}, Reachable states: ${d.stateCount}`);
      console.log(`       Line: ${d.line}`);
      console.log(`       Block: ${d.block.substring(0, 120)}...`);
    });

    const totalCases = dispatchers.reduce((s, d) => s + d.caseCount, 0);
    const totalStates = dispatchers.reduce((s, d) => s + (typeof d.stateCount === 'number' ? d.stateCount : 0), 0);

    console.log('');
    console.log('  Recovery feasibility:');
    console.log(`    Total dispatchers:     ${dispatchers.length}`);
    console.log(`    Total cases:           ${totalCases}`);
    console.log(`    Unique states:         ${totalStates}`);
    console.log('');

    if (totalStates > 0 && totalCases > 0) {
      const recoveryPct = Math.round(totalStates / totalCases * 100);
      console.log(`    State coverage:        ${recoveryPct}% (${totalStates}/${totalCases})`);
      if (recoveryPct > 60) {
        console.log('    Verdict: RECOVERABLE — enough state info to reconstruct');
        console.log('    Recovery strategy: trace each case → map successor states → rebuild if/else chain');
      } else if (recoveryPct > 30) {
        console.log('    Verdict: PARTIAL — some states unreachable via static analysis');
        console.log('    Recovery strategy: hybrid static + dynamic tracing needed');
      } else {
        console.log('    Verdict: HEAVILY_OBFUSCATED — state graph is dense, manual analysis recommended');
      }
    }
  }

  console.log('');
  console.log('  Overall CFF metrics:');
  console.log(`    Switch statements:     ${complexity.switchStatements}`);
  console.log(`    while(true) loops:     ${complexity.whileTrue}`);
  console.log(`    break statements:      ${complexity.breakStatements}`);
  console.log(`    default cases:         ${complexity.defaultCases}`);
  console.log(`    CFF score:             ${complexity.cffScore} [${complexity.verdict}]`);
  console.log('');
}

module.exports = { analyzeDispatcher, estimateCffComplexity, analyzeCFF, CFF_PATTERNS };
