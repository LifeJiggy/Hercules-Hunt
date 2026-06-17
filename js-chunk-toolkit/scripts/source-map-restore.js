const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function downloadMap(jsUrl, outputDir) {
  const mapUrl = jsUrl + '.map';
  const filename = path.basename(jsUrl) + '.map';
  const outputPath = path.join(outputDir, filename);
  try {
    execSync(`curl.exe -sL -o "${outputPath}" "${mapUrl}"`, { stdio: 'pipe' });
    const stat = fs.statSync(outputPath);
    if (stat.size > 100) {
      console.log(`  Downloaded: ${filename} (${(stat.size / 1024).toFixed(1)} KB)`);
      return outputPath;
    }
    fs.unlinkSync(outputPath);
  } catch (e) {}
  return null;
}



function report(results, mapFile) {
  const basename = path.basename(mapFile, '.map');

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Source Map: ${basename}.map`);
  console.log(`${'='.repeat(70)}`);

  console.log(`\n[1] Basic Metadata`);
  console.log(`  ${'-'.repeat(50)}`);
  console.log(`  Version:      ${results.version || 'N/A'}`);
  console.log(`  Target File:  ${results.file || 'N/A'}`);
  console.log(`  Sources:      ${results.sourceCount}`);
  console.log(`  Names:        ${results.namesCount}`);
  console.log(`  Has Content:  ${results.hasContent ? 'YES (gold!)' : 'NO (metadata only)'}`);
  if (results.mappingsLen) console.log(`  Mappings Len: ${results.mappingsLen} chars`);

  console.log(`\n[2] Interesting Source Files`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.interestingSources.length > 0) {
    results.interestingSources.forEach(s => console.log(`  ${s}`));
  } else { console.log(`  None`); }

  console.log(`\n[3] Interesting Names`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.interestingNames.length > 0) {
    results.interestingNames.forEach(n => console.log(`  ${n}`));
  } else { console.log(`  None`); }

  console.log(`\n[4] Secrets Found in Source Content`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.secrets.length > 0) {
    const seen = new Set();
    results.secrets.slice(0, 50).forEach(s => {
      const key = `${s.type}:${s.value}`;
      if (!seen.has(key)) {
        seen.add(key);
        console.log(`  [${s.type}] ${s.value}`);
      }
    });
    if (results.secrets.length > 50) console.log(`  ... and ${results.secrets.length - 50} more (see restored_sources/)`);
  } else if (results.hasContent) {
    console.log(`  No high-confidence secrets found. Check restored_sources/.`);
  } else { console.log(`  No source content available to scan`); }

  console.log(`\n[5] Source Map Validation`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.validation) {
    const v = results.validation;
    console.log(`  ${v.valid ? 'VALID' : 'INVALID'} source map structure`);
    if (v.warnings.length > 0) v.warnings.forEach(w => console.log(`  Warning: ${w}`));
  }

  console.log(`\n[6] Minifier / Compiler Fingerprint`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.minifier) {
    console.log(`  ${results.minifier.name} (confidence: ${results.minifier.confidence})`);
  } else { console.log(`  Unknown / custom`); }

  console.log(`\n[7] VLQ Mappings Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.mappingAnalysis) {
    const ma = results.mappingAnalysis;
    console.log(`  Total mappings: ${ma.total}`);
    console.log(`  Sources mapped: ${ma.sourceCount}`);
    console.log(`  Names mapped: ${ma.nameCount}`);
    console.log(`  Coverage ratio: ${ma.coverageRatio}`);
    console.log(`  Density: ${ma.density} lines/mapping`);
  }

  console.log(`\n[8] V3 Extensions`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.v3extensions) {
    const v3 = results.v3extensions;
    if (v3.ignoreList) console.log(`  x_google_ignoreList: ${v3.ignoreListCount} sources ignored`);
    if (v3.other.length > 0) v3.other.forEach(e => console.log(`  ${e}`));
    if (!v3.ignoreList && v3.other.length === 0) console.log(`  No V3 extensions detected`);
  }

  console.log(`\n[9] Variable Name Recovery`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.variableNames) {
    const vn = results.variableNames;
    if (vn.mangledCount > 0) console.log(`  Mangled names: ${vn.mangledCount} (${(vn.mangledRatio * 100).toFixed(0)}% of total)`);
    if (vn.suspicious.length > 0) vn.suspicious.slice(0, 20).forEach(n => console.log(`  ${n}`));
  }

  console.log(`\n[10] Original Source Estimation`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.originalEstimate) {
    const oe = results.originalEstimate;
    console.log(`  Estimated original lines: ${oe.estimatedLines}`);
    console.log(`  Source-to-map ratio: ${oe.ratio}x`);
    console.log(`  Language: ${oe.language || 'Unknown'}`);
  }

  console.log(`\n[11] Dependency / Entry Point Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  if (results.deps) {
    if (results.deps.entries.length > 0) {
      console.log(`  Entry points:`);
      results.deps.entries.forEach(e => console.log(`    ${e}`));
    }
    if (results.deps.common.length > 0) {
      console.log(`  Common/shared modules (${results.deps.common.length}):`);
      results.deps.common.slice(0, 10).forEach(d => console.log(`    ${d}`));
    }
  }

  console.log(`\n${'='.repeat(70)}\n`);
}

// -- Feature 5: Source Map Validation & Integrity --
function validateMapIntegrity(data) {
  const warnings = [];
  if (!data.version || data.version !== 3) warnings.push(`Expected version 3, got ${data.version}`);
  if (!data.mappings) warnings.push('No mappings field');
  if (!data.sources || data.sources.length === 0) warnings.push('No sources listed');
  if (!data.names) warnings.push('No names field (optional but unusual)');
  if (data.sourcesContent && data.sources.length !== data.sourcesContent.length) {
    warnings.push(`Sources count (${data.sources.length}) != sourcesContent count (${data.sourcesContent.length})`);
  }
  if (data.mappings) {
    const vlcCount = (data.mappings.match(/[;,]/g) || []).length + 1;
    if (vlcCount < 2) warnings.push('Mappings appear empty or trivial');
  }
  if (data.file && !data.file.endsWith('.js') && !data.file.endsWith('.mjs') && !data.file.endsWith('.cjs')) {
    warnings.push(`Target file unusual extension: ${data.file}`);
  }
  return { valid: warnings.length === 0, warnings };
}

// -- Feature 6: Minifier Fingerprinting --
function fingerprintMinifier(data) {
  const markers = [
    { name: 'webpack', confidence: 'HIGH', test: () => data.sourceRoot && /webpack/i.test(data.sourceRoot) || (data.sources || []).some(s => /webpack/i.test(s)) },
    { name: 'webpack', confidence: 'MEDIUM', test: () => (data.sources || []).some(s => s.includes('~') && s.match(/\.\w+$/)) },
    { name: 'Terser', confidence: 'HIGH', test: () => (data.names || []).length < 100 && (data.sources || []).some(s => /\.min\.js/.test(data.file)) },
    { name: 'esbuild', confidence: 'HIGH', test: () => /esbuild/i.test(data.file || '') || (data.sources || []).some(s => /esbuild/i.test(s)) },
    { name: 'Rollup', confidence: 'HIGH', test: () => (data.names || []).length === 0 && (data.sources || []).some(s => s.startsWith('\0')) },
    { name: 'Babel', confidence: 'MEDIUM', test: () => data.file && /bundle\.js/i.test(data.file) && !data.sourceRoot },
    { name: 'GCC (Closure)', confidence: 'MEDIUM', test: () => (data.names || []).filter(n => n.length === 1).length > 100 },
    { name: 'Parcel', confidence: 'MEDIUM', test: () => data.sourceRoot && /parcel/i.test(data.sourceRoot) },
    { name: 'Next.js', confidence: 'HIGH', test: () => data.sourceRoot && /\.next/i.test(data.sourceRoot) || (data.sources || []).some(s => /\/\.next\//i.test(s)) },
    { name: 'Vite', confidence: 'MEDIUM', test: () => data.file && /vite/i.test(data.file) || (data.sources || []).some(s => s.startsWith('/') && !s.startsWith('//')) },
  ];
  for (const m of markers) {
    if (m.test()) return { name: m.name, confidence: m.confidence };
  }
  return null;
}

// -- Feature 7: VLQ Mappings Analysis --
function analyzeMappings(data) {
  if (!data.mappings) return null;
  const segments = data.mappings.split(';');
  const totalSegments = segments.length;
  let nameRefs = 0; let sourceRefs = 0;
  for (const seg of segments) {
    if (seg.includes(',')) {
      const parts = seg.split(',');
      parts.forEach(p => {
        const fields = p.match(/[A-Za-z0-9+/=]+/g) || [];
        if (fields.length >= 4) sourceRefs++;
        if (fields.length >= 5) nameRefs++;
      });
    } else if (seg.length > 0) {
      const fields = seg.match(/[A-Za-z0-9+/=]+/g) || [];
      if (fields.length >= 4) sourceRefs++;
      if (fields.length >= 5) nameRefs++;
    }
  }
  return {
    total: totalSegments,
    sourceCount: sourceRefs,
    nameCount: nameRefs,
    density: totalSegments > 0 ? (totalSegments / Math.max(1, totalSegments)).toFixed(2) : '0',
    coverageRatio: totalSegments > 0 ? `${((sourceRefs / totalSegments) * 100).toFixed(1)}%` : '0%',
  };
}

// -- Feature 8: V3 Extension Detection --
function detectV3Extensions(data) {
  const results = { ignoreList: false, ignoreListCount: 0, other: [] };
  if (data.x_google_ignoreList) {
    results.ignoreList = true;
    results.ignoreListCount = data.x_google_ignoreList.length;
  }
  if (data.x_facebook_sources) results.other.push('x_facebook_sources');
  if (data.x_react_custom) results.other.push('x_react_custom');
  if (data.x_react_profile) results.other.push('x_react_profile');
  const extraKeys = Object.keys(data).filter(k => k.startsWith('x_') && k !== 'x_google_ignoreList');
  extraKeys.forEach(k => { if (!results.other.includes(k)) results.other.push(k); });
  return results;
}

// -- Feature 9: Variable Name Recovery --
function recoverVariableNames(data) {
  if (!data.names || data.names.length === 0) return null;
  const singleChar = data.names.filter(n => n.length === 1);
  const shortNames = data.names.filter(n => n.length >= 2 && n.length <= 3);
  const hexNames = data.names.filter(n => /^_0x[a-f0-9]{2,}/.test(n));
  const suspicious = [];
  const keywords = ['secret', 'token', 'key', 'password', 'api', 'admin', 'internal', 'config', 'auth', 'debug', 'private', 'hidden', 'bypass', 'backdoor'];
  data.names.forEach(n => {
    if (keywords.some(k => n.toLowerCase().includes(k))) suspicious.push(n);
  });
  return {
    total: data.names.length,
    mangledCount: singleChar.length,
    mangledRatio: data.names.length > 0 ? singleChar.length / data.names.length : 0,
    shortCount: shortNames.length,
    hexCount: hexNames.length,
    suspicious: [...new Set(suspicious)],
  };
}

// -- Feature 10: Original Source Estimation --
function estimateOriginalSource(data, mapFile) {
  const mapStat = fs.statSync(mapFile);
  const mapSizeKB = (mapStat.size / 1024).toFixed(1);
  let estimatedLines = 0;
  let language = 'JavaScript';
  if (data.sources) {
    const fileExts = data.sources.map(s => path.extname(s).toLowerCase());
    const extCounts = {};
    fileExts.forEach(e => { if (e) extCounts[e] = (extCounts[e] || 0) + 1; });
    const topExt = Object.entries(extCounts).sort((a, b) => b[1] - a[1])[0];
    if (topExt) {
      const langMap = { '.ts': 'TypeScript', '.tsx': 'TypeScript (React)', '.jsx': 'React JSX', '.vue': 'Vue', '.svelte': 'Svelte', '.scss': 'SCSS', '.less': 'Less', '.css': 'CSS', '.html': 'HTML', '.json': 'JSON' };
      language = langMap[topExt[0]] || topExt[0];
    }
  }
  if (data.mappings) {
    const semicolons = (data.mappings.match(/;/g) || []).length;
    estimatedLines = semicolons || data.sourcesContent ? data.sourcesContent.reduce((s, c) => s + (c ? c.split('\n').length : 0), 0) : 0;
  }
  return {
    mapSizeKB,
    estimatedLines,
    sourceFiles: data.sources ? data.sources.length : 0,
    language,
    ratio: estimatedLines > 0 ? (mapSizeKB / Math.max(1, estimatedLines)).toFixed(3) : '0',
  };
}

// -- Feature 11: Dependency & Entry Point Analysis --
function analyzeDependencies(data) {
  if (!data.sources) return null;
  const entries = [];
  const common = [];
  data.sources.forEach(s => {
    if (/index\.(js|ts|jsx|tsx)$/.test(s) || /main\.(js|ts|jsx|tsx)$/.test(s) || /app\.(js|ts|jsx|tsx)$/.test(s)) {
      entries.push(s);
    }
    if (/node_modules/.test(s) || /vendor/.test(s)) {
      common.push(s.replace(/^.*node_modules\//, ''));
    }
  });
  return { entries: [...new Set(entries)], common: [...new Set(common)] };
}

// -- Enhanced parseSourceMap with new features --
function parseSourceMap(mapFile, outputDir) {
  const data = JSON.parse(fs.readFileSync(mapFile, 'utf-8'));
  const results = {
    version: data.version,
    file: data.file,
    sourceCount: (data.sources || []).length,
    namesCount: (data.names || []).length,
    hasContent: !!(data.sourcesContent),
    mappingsLen: data.mappings ? data.mappings.length : 0,
    interestingSources: [],
    interestingNames: [],
    secrets: [],
    validation: null,
    minifier: null,
    mappingAnalysis: null,
    v3extensions: null,
    variableNames: null,
    originalEstimate: null,
    deps: null,
  };

  if (data.sources) {
    for (const src of data.sources) {
      if (/api|admin|internal|secret|token|config|auth|key|graphql|firebase|stripe|aws|private|debug/.test(src)) {
        results.interestingSources.push(src);
      }
    }
  }

  if (data.names) {
    const kw = ['secret', 'token', 'key', 'password', 'api', 'admin', 'internal', 'debug', 'hidden'];
    for (const name of data.names) {
      if (kw.some(k => name.toLowerCase().includes(k))) {
        results.interestingNames.push(name);
      }
    }
  }

  if (data.sourcesContent) {
    const secretPatterns = [
      { label: 'AWS Key', regex: /AKIA[A-Z0-9]{16}/g },
      { label: 'GCP API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
      { label: 'Stripe Live Secret', regex: /sk_live_[A-Za-z0-9]{24,}/g },
      { label: 'Stripe Publishable', regex: /pk_(live|test)_[A-Za-z0-9]{24,}/g },
      { label: 'GitHub Token', regex: /gh[psoubr]_[A-Za-z0-9_]{36,}/g },
      { label: 'JWT', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
      { label: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9]{10,}/g },
      { label: 'Firebase URL', regex: /[a-z0-9-]+\.firebaseio\.com/g },
      { label: 'OpenAI Key', regex: /sk-[A-Za-z0-9]{20,}/g },
      { label: 'SendGrid Key', regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g },
      { label: 'Auth0 Domain', regex: /[a-zA-Z0-9-]+\.auth0\.com/g },
      { label: 'Mapbox Token', regex: /pk\.eyJ[A-Za-z0-9_-]{60,}/g },
      { label: 'Twilio SID', regex: /AC[A-Z0-9a-z]{32}/g },
    ];

    const sourcesDir = path.join(outputDir, 'restored_sources');
    if (!fs.existsSync(sourcesDir)) fs.mkdirSync(sourcesDir, { recursive: true });

    for (let i = 0; i < data.sourcesContent.length; i++) {
      const content = data.sourcesContent[i];
      if (!content) continue;
      const srcName = (data.sources && data.sources[i]) ? data.sources[i] : `unknown_${i}`;
      const outFile = path.join(sourcesDir, path.basename(srcName));
      fs.writeFileSync(outFile, content);
      for (const p of secretPatterns) {
        let match;
        while ((match = p.regex.exec(content)) !== null) {
          results.secrets.push({ file: srcName, type: p.label, value: match[0].substring(0, 100) });
        }
      }
    }

    const allContent = data.sourcesContent.filter(Boolean).join('\n');
    const apiEndpointRegex = /["'](https?:\/\/[^"']*\/(?:api|v[0-9]+|rest|graphql|internal|backend|admin|private)[a-zA-Z0-9_\-/{}:]*)["']/g;
    let match;
    while ((match = apiEndpointRegex.exec(allContent)) !== null) {
      results.secrets.push({ file: '(multiple)', type: 'API Endpoint', value: match[1].substring(0, 150) });
    }
  }

  results.validation = validateMapIntegrity(data);
  results.minifier = fingerprintMinifier(data);
  results.mappingAnalysis = analyzeMappings(data);
  results.v3extensions = detectV3Extensions(data);
  results.variableNames = recoverVariableNames(data);
  results.originalEstimate = estimateOriginalSource(data, mapFile);
  results.deps = analyzeDependencies(data);

  return results;
}

const args = process.argv.slice(2);
if (args.length < 1) {
  console.log(`Usage:`);
  console.log(`  node source-map-restore.js <directory_of_maps>`);
  console.log(`  node source-map-restore.js <single.map>`);
  console.log(`  node source-map-restore.js download <js_url> <output_dir>`);
  process.exit(1);
}

const cmd = args[0];

if (cmd === 'download' && args.length >= 2) {
  const jsUrl = args[1];
  const outputDir = args[2] || 'sourcemaps';
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  console.log(`\n[*] Attempting source map download from: ${jsUrl}.map`);
  const mapPath = downloadMap(jsUrl, outputDir);
  if (!mapPath) {
    console.log(`[!] Source map not available at ${jsUrl}.map`);
    process.exit(1);
  }
  const results = parseSourceMap(mapPath, outputDir);
  report(results, mapPath);
} else if (fs.statSync(cmd).isDirectory()) {
  const maps = fs.readdirSync(cmd).filter(f => f.endsWith('.map'));
  if (maps.length === 0) {
    console.log(`No .map files found in ${cmd}`);
    process.exit(1);
  }
  const outDir = path.join(cmd, '..', 'output', 'sourcemap_restored');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  for (const mapFile of maps) {
    const mapPath = path.join(cmd, mapFile);
    const results = parseSourceMap(mapPath, outDir);
    report(results, mapPath);
  }
} else if (cmd.endsWith('.map')) {
  const outDir = path.join(path.dirname(cmd), '..', 'output', 'sourcemap_restored');
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const results = parseSourceMap(cmd, outDir);
  report(results, cmd);
} else {
  console.log(`Unrecognized command: ${cmd}`);
  process.exit(1);
}
