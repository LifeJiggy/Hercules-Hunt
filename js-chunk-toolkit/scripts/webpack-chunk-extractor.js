const fs = require('fs');
const path = require('path');
const vm = require('vm');

function extractChunkManifest(code) {
  const results = [];
  const patterns = [
    { desc: 'Chunk hash mapping', regex: /\{(\s*"\d+":"[a-f0-9]+"\s*(?:,\s*)?)+\}/g },
    { desc: 'Chunk filenames', regex: /["']([a-f0-9]{8,}\.js)["']/g },
    { desc: 'Numeric chunks', regex: /"\d+\.chunk\.js"/g },
    { desc: 'Named chunks (webpack 5)', regex: /["']([a-zA-Z_]+~[a-zA-Z_]+(?:~[a-zA-Z_]+)*\.chunk\.js)["']/g },
  ];
  for (const p of patterns) {
    let match;
    while ((match = p.regex.exec(code)) !== null) {
      results.push({ type: p.desc, value: match[1] || match[0] });
    }
  }
  return results;
}

function extractPublicPath(code) {
  const match = code.match(/__webpack_require__\.p\s*=\s*["']([^"']*)["']/);
  return match ? match[1] : null;
}

function extractModuleMap(code) {
  const results = { numeric: [], named: [], interesting: [] };
  const namedRegex = /"((?:\.\/)?(?:src\/)?[a-zA-Z0-9_\/-]+\.(?:js|ts|jsx|tsx|json|vue|jsx))":\s*function/g;
  let match;
  while ((match = namedRegex.exec(code)) !== null) {
    results.named.push(match[1]);
    if (/api|admin|internal|secret|token|config|auth|key|graphql|firebase|stripe|aws/.test(match[1])) {
      results.interesting.push(match[1]);
    }
  }
  if (results.named.length === 0) {
    const idRegex = /"(\d+)":\s*function/g;
    while ((match = idRegex.exec(code)) !== null) {
      results.numeric.push(parseInt(match[1]));
    }
  }
  return results;
}

function extractDynamicImports(code) {
  const results = [];
  const patterns = [
    /import\(["']([^"']+)["']\)/g,
    /__webpack_require__\.e\s*\(\s*(?:\/\*! import\(\) \*\/\s*)?(\d+)/g,
    /Promise\.all\(\[[^\]]*__webpack_require__\.e\((\d+)/g,
    /require\.ensure\(["']([^"']+)["']/g,
  ];
  for (const regex of patterns) {
    let match;
    while ((match = regex.exec(code)) !== null) {
      results.push(match[1] || match[0]);
    }
  }
  return results;
}

function extractChunkLoadingFunction(code) {
  const match = code.match(/__webpack_require__\.u\s*=\s*function\s*\(\s*\w+\s*\)\s*\{([^}]+)\}/);
  if (match) return match[1].trim();
  return null;
}

function extractInstallChunks(code) {
  const results = [];
  const regex = /installedChunks\s*=\s*\{([^}]+)\}/g;
  let match;
  while ((match = regex.exec(code)) !== null) {
    match[1].split(',').filter(s => s.trim()).forEach(s => {
      const parts = s.trim().split(':');
      if (parts.length === 2) results.push({ id: parts[0].trim(), status: parts[1].trim() });
    });
  }
  return results;
}

function extractNextJsChunks(code) {
  const results = [];
  const pageRegex = /["']pages\/([a-zA-Z0-9_\/\[\]]+)["']/g;
  let match;
  while ((match = pageRegex.exec(code)) !== null) {
    results.push({ framework: 'Next.js', type: 'page', path: match[1] });
  }
  return results;
}

function extractModuleIdToName(code) {
  const results = [];
  const regex = /module\.id\s*=\s*["']([^"']+)["']/g;
  let match;
  while ((match = regex.exec(code)) !== null) results.push(match[1]);
  return results;
}

function extractRuntimeChunkNames(code) {
  const results = [];
  const patterns = [
    /["']([^"']+\/pages\/[^"']+\.js)["']/g,
    /["']([^"']+\/chunks\/[^"']+\.js)["']/g,
    /["'](framework-[a-f0-9]+\.js)["']/g,
    /["'](main-[a-f0-9]+\.js)["']/g,
    /["'](vendor-[a-f0-9]+\.js)["']/g,
    /["'](commons-[a-f0-9]+\.js)["']/g,
    /["'](runtime~[a-f0-9]+\.js)["']/g,
    /["'](\d+\.[a-f0-9]+\.chunk\.js)["']/g,
  ];
  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(code)) !== null) results.push(match[1]);
  }
  return [...new Set(results)];
}

function extractAllJsUrls(code) {
  const results = [];
  const urlRegex = /["'](https?:\/\/[^"']+\.js(?:\?[^"']*)?)["']/g;
  let match;
  while ((match = urlRegex.exec(code)) !== null) results.push(match[1]);
  return results;
}

// -- Feature 9: Build Metadata Extraction --
function extractBuildMetadata(code) {
  const meta = {};
  const versionMatch = code.match(/webpack[/\\]bundle[/\\]v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)/);
  if (versionMatch) meta.version = `${versionMatch[1]}.${versionMatch[2]}.${versionMatch[3]}`;
  const modeMatch = code.match(/["']mode["']\s*[:=]\s*["'](development|production|none)["']/i);
  if (modeMatch) meta.mode = modeMatch[1];
  const targetMatch = code.match(/["']target["']\s*[:=]\s*["']([^"']+)["']/i);
  if (targetMatch) meta.target = targetMatch[1];
  const hashMatch = code.match(/__webpack_hash__\s*=\s*["']([^"']+)["']/);
  if (hashMatch) meta.buildHash = hashMatch[1];
  const timestampMatch = code.match(/["']builtAt["']\s*[:=]\s*(\d{10,})/);
  if (timestampMatch) meta.builtAt = new Date(parseInt(timestampMatch[1]) * 1000).toISOString();
  const envMatch = code.match(/["']NODE_ENV["']\s*[:=]\s*["']([^"']+)["']/i);
  if (envMatch) meta.nodeEnv = envMatch[1];
  return meta;
}

// -- Feature 10: Entry Point Reconstruction --
function extractEntryPoints(code) {
  const results = [];
  const entryRegex = /["']entry["']\s*[:=]\s*\{([^}]+)\}/gi;
  let match;
  while ((match = entryRegex.exec(code)) !== null) {
    const entries = match[1].match(/"(\w+)":\s*["']([^"']+)["']/g);
    if (entries) entries.forEach(e => {
      const parts = e.match(/"(\w+)":\s*["']([^"']+)["']/);
      if (parts) results.push({ name: parts[1], path: parts[2] });
    });
  }
  if (results.length === 0) {
    const mainMatch = code.match(/["']\.\/src\/index["']|["']\.\/index["']|["']\.\/src\/main["']/g);
    if (mainMatch) results.push({ name: 'main (inferred)', path: mainMatch[0] });
  }
  return results;
}

// -- Feature 11: Module Dependency Graph --
function extractDependencyGraph(code) {
  const results = { edges: [], hubs: [] };
  const depRegex = /__webpack_require__\(\s*["']?(\d+|\.\/[^"')]+)["']?\s*\)/g;
  let match;
  const deps = {};
  while ((match = depRegex.exec(code)) !== null) {
    const dep = match[1];
    deps[dep] = (deps[dep] || 0) + 1;
  }
  const entries = Object.entries(deps).sort((a, b) => b[1] - a[1]);
  results.hubs = entries.slice(0, 15).map(([mod, count]) => ({ module: mod, references: count }));
  results.edges = entries.length;
  return results;
}

// -- Feature 12: Circular Dependency Detection --
function detectCircularDeps(code) {
  const results = [];
  const circularRegex = /\.\.\/[^"'`]+|dep_of_dep|circular|cycle/gi;
  let match;
  while ((match = circularRegex.exec(code)) !== null) {
    if (match[0].length > 3) results.push(match[0]);
  }
  const moduleRefs = {};
  const requireRegex = /__webpack_require__\(\s*["'](\d+)["']\s*\)/g;
  let m;
  while ((m = requireRegex.exec(code)) !== null) {
    const id = m[1];
    if (moduleRefs[id]) moduleRefs[id]++;
    else moduleRefs[id] = 1;
  }
  return { warnings: [...new Set(results)], moduleRefCount: Object.keys(moduleRefs).length };
}

// -- Feature 13: Vendor Library Fingerprinting --
function fingerprintVendors(code) {
  const results = [];
  const vendorPatterns = [
    { name: 'React', patterns: [/__REACT_DEVTOOLS/, /react-production-min/, /createElement/, /useState\s*\(/] },
    { name: 'ReactDOM', patterns: [/ReactDOM\.render|hydrateRoot/] },
    { name: 'jQuery', patterns: [/jQuery\s*=|jquery@|\.on\(["']click["']/] },
    { name: 'Lodash', patterns: [/lodash@|\.\_\.|\.debounce|_.escape/] },
    { name: 'Axios', patterns: [/axios@|\.defaults\.baseURL/] },
    { name: 'Moment', patterns: [/moment@|moment\(\)\./] },
    { name: 'Bootstrap', patterns: [/bootstrap@|data-toggle|data-target/] },
    { name: 'Chart.js', patterns: [/Chart\.register|new Chart\(/] },
    { name: 'D3', patterns: [/d3@|d3\.select|d3\.scale/] },
    { name: 'Express', patterns: [/express@|express\.Router/] },
    { name: 'Vue', patterns: [/createApp|Vue\.component/] },
    { name: 'Angular', patterns: [/@angular\/core|platformBrowserDynamic/] },
    { name: 'Next.js', patterns: [/next@|'next\/|"next\//] },
    { name: 'GSAP', patterns: [/gsap@|TweenMax|TimelineMax/] },
    { name: 'Three.js', patterns: [/three@|THREE\./] },
    { name: 'Socket.IO', patterns: [/socket\.io@|io\(["']/] },
    { name: 'Redux', patterns: [/redux@|createStore|useSelector/] },
    { name: 'Zustand', patterns: [/zustand@|create\(\(set\)/] },
    { name: 'React Router', patterns: [/react-router@|BrowserRouter|createBrowserRouter/] },
    { name: 'Firebase', patterns: [/firebase@|firebase\.initializeApp/] },
  ];
  for (const vp of vendorPatterns) {
    const found = vp.patterns.some(p => p.test(code));
    if (found) results.push(vp.name);
  }
  return results;
}

// -- Feature 14: Code Splitting Strategy Analysis --
function analyzeCodeSplitting(code) {
  const results = { strategies: [], chunkGroups: 0 };
  if (/import\s*\(/.test(code)) results.strategies.push('Dynamic import()');
  if (/__webpack_require__\.e\s*\(/.test(code)) results.strategies.push('webpack require.e');
  if (/require\.ensure/.test(code)) results.strategies.push('require.ensure (legacy)');
  if (/Promise\.all\(\[[^\]]*__webpack_require__\.e/.test(code)) results.strategies.push('Parallel chunk loading');
  if (/prefetch|__webpack_require__\.f\./.test(code)) results.strategies.push('Prefetch / preload');
  if (/webpackChunkName/.test(code)) results.strategies.push('Named chunks (magic comments)');
  if (/webpackPrefetch/.test(code)) results.strategies.push('Prefetch hint (magic comments)');
  if (/webpackPreload/.test(code)) results.strategies.push('Preload hint (magic comments)');
  const lazyCount = (code.match(/import\s*\(/g) || []).length;
  const eagerCount = (code.match(/__webpack_require__\s*\(\s*"(\d+)"/g) || []).length;
  results.chunkGroups = { lazy: lazyCount, eager: eagerCount };
  return results;
}

// -- Feature 15: Async Boundary Detection --
function detectAsyncBoundaries(code) {
  const results = [];
  const patterns = [
    { label: 'import() boundaries', re: /import\s*\(\s*(?:\/\*[^*]*\*\/\s*)?["'`]([^"'`]+)["'`]/g },
    { label: 'require.ensure', re: /require\.ensure\s*\(/g },
    { label: 'Promise.all chunks', re: /Promise\.all\s*\([^)]*__webpack_require__\.e/g },
    { label: 'Async chunk callback', re: /__webpack_require__\.e\s*\([^)]+\)\.then/g },
    { label: 'Chunk error handler', re: /\.catch\s*\([^)]*chunkFailed/g },
  ];
  for (const p of patterns) {
    let match; let count = 0;
    while ((match = p.re.exec(code)) !== null) count++;
    if (count > 0) results.push({ type: p.label, count });
  }
  return results;
}

// -- Feature 16: Webpack Plugin Fingerprinting --
function detectWebpackPlugins(code) {
  const results = [];
  const pluginPatterns = [
    { name: 'DefinePlugin', patterns: [/__DEV__|__PRODUCTION__|process\.env\.NODE_ENV\s*!==\s*["']production["']/] },
    { name: 'ProvidePlugin', patterns: [/\$\.extend|_\.isArray|React\.createElement/] },
    { name: 'MiniCssExtractPlugin', patterns: [/mini-css-extract|\.css\.[a-f0-9]+\.chunk\.css/] },
    { name: 'HtmlWebpackPlugin', patterns: [/HtmlWebpackPlugin|__html_webpack_/] },
    { name: 'TerserPlugin', patterns: [/class\s*\w+\s*\{[^}]*this\.\w/] },
    { name: 'ModuleConcatenationPlugin', patterns: [/\/\*\! \*\s+concatenated|__webpack_require__\.c\s*=\s*module/] },
    { name: 'SourceMapDevToolPlugin', patterns: [/sourceMappingURL=[^"']+\.map/] },
    { name: 'BundleAnalyzerPlugin', patterns: [/webpack-bundle-analyzer|stats\.json/] },
    { name: 'CircularDependencyPlugin', patterns: [/circular|CIRCULAR_DEPENDENCY/i] },
    { name: 'ForkTsCheckerPlugin', patterns: [/fork-ts-checker|ForkTsCheckerWebpackPlugin/] },
    { name: 'CopyWebpackPlugin', patterns: [/copy-webpack-plugin|copyPlugin/i] },
    { name: 'ESLintPlugin', patterns: [/eslint-webpack-plugin|ESLintPlugin/i] },
    { name: 'WorkboxPlugin', patterns: [/workbox-webpack|workbox\.precaching/] },
    { name: 'ManifestPlugin', patterns: [/webpack-manifest-plugin|manifest\.json/] },
    { name: 'CompressionPlugin', patterns: [/\.gz|\.br|gzip|brotli/] },
  ];
  for (const pp of pluginPatterns) {
    if (pp.patterns.some(p => p.test(code))) results.push(pp.name);
  }
  return results;
}

// -- Feature 17: Module Concatenation / Scope Hoisting Detection --
function detectConcatScopeHoisting(code) {
  const results = [];
  const concatMatch = code.match(/\/\*\! \*\s+concatenated/g);
  if (concatMatch) results.push({ type: 'ModuleConcatenation', count: concatMatch.length });
  const scopeHoist = code.match(/__webpack_exports__\s*=\s*\{[^}]*}/g);
  if (scopeHoist) {
    const total = scopeHoist.filter(s => s.length < 200).length;
    if (total > 0) results.push({ type: 'Scope Hoisted Modules', count: total });
  }
  const noConcat = code.match(/\/\/\s*module\s+concatenation\s+is\s+disabled/i);
  if (noConcat) results.push({ type: 'Concatenation Disabled', detail: noConcat[0] });
  return results;
}

// -- Feature 18: Bundle Budget Analysis --
function analyzeBundleBudget(code) {
  const lines = code.split('\n');
  const totalChars = code.length;
  const totalLines = lines.length;
  const maxLineLen = Math.max(...lines.map(l => l.length));
  const avgLineLen = Math.round(totalChars / totalLines);
  const funcCount = (code.match(/function\s*\w*\s*\(/g) || []).length;
  const varCount = (code.match(/\b(?:var|let|const)\s+\w+\s*[=;]/g) || []).length;
  const commentCount = (code.match(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g) || []).length;
  const emptyLines = lines.filter(l => l.trim() === '').length;
  const stringCount = (code.match(/["'`][^"'`]{4,}["'`]/g) || []).length;
  const budget = {
    totalChars, totalLines, maxLineLen, avgLineLen,
    functions: funcCount, variables: varCount,
    comments: commentCount, emptyLines, strings: stringCount,
    density: (funcCount / (totalLines || 1)).toFixed(3),
  };
  return budget;
}

function analyze(inputFile) {
  if (!fs.existsSync(inputFile)) {
    console.error(`File not found: ${inputFile}`);
    process.exit(1);
  }

  const code = fs.readFileSync(inputFile, 'utf-8');
  const filename = path.basename(inputFile);

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Webpack Chunk Analysis: ${filename}`);
  console.log(`${'='.repeat(70)}`);

  if (!/__webpack_require__|webpackJsonp|webpackChunk/.test(code)) {
    console.log(`  [!] This file does not appear to be a webpack bundle.`);
    console.log(`      Missing __webpack_require__, webpackJsonp, or webpackChunk signature.`);
    return;
  }

  console.log(`\n[1] Public Path`);
  console.log(`  ${'-'.repeat(50)}`);
  const publicPath = extractPublicPath(code);
  console.log(`  ${publicPath ? publicPath : '(not explicitly set / default root)'}`);

  console.log(`\n[2] Module Map`);
  console.log(`  ${'-'.repeat(50)}`);
  const modules = extractModuleMap(code);
  if (modules.named.length > 0) {
    console.log(`  Total named modules: ${modules.named.length}`);
  }
  if (modules.numeric.length > 0) {
    console.log(`  Total numeric modules: ${modules.numeric.length}`);
    console.log(`  Module ID range: ${Math.min(...modules.numeric)} - ${Math.max(...modules.numeric)}`);
  }

  if (modules.interesting.length > 0) {
    console.log(`\n  [!] Interesting modules (API/admin/secret/etc):`);
    modules.interesting.forEach(m => console.log(`    ${m}`));
  }

  console.log(`\n[3] Chunk Manifest`);
  console.log(`  ${'-'.repeat(50)}`);
  const chunks = extractChunkManifest(code);
  if (chunks.length > 0) {
    const unique = [...new Set(chunks.map(c => c.value))];
    unique.forEach(c => console.log(`  ${c}`));
  } else {
    console.log(`  No explicit chunk entries found in this file`);
  }

  console.log(`\n[4] Chunk Filenames / Runtime Names`);
  console.log(`  ${'-'.repeat(50)}`);
  const runtimeChunks = extractRuntimeChunkNames(code);
  if (runtimeChunks.length > 0) {
    runtimeChunks.forEach(c => console.log(`  ${c}`));
  } else {
    console.log(`  None found`);
  }

  console.log(`\n[5] Dynamic Imports (lazy-loaded chunks)`);
  console.log(`  ${'-'.repeat(50)}`);
  const imports = extractDynamicImports(code);
  if (imports.length > 0) {
    [...new Set(imports)].forEach(i => console.log(`  ${i}`));
  } else {
    console.log(`  None found`);
  }

  const chunkFn = extractChunkLoadingFunction(code);
  if (chunkFn) {
    console.log(`\n[6] Chunk Loading Function`);
    console.log(`  ${'-'.repeat(50)}`);
    console.log(`  ${chunkFn}`);
  }

  console.log(`\n[7] Next.js Pages / Framework Routes`);
  console.log(`  ${'-'.repeat(50)}`);
  const nextjs = extractNextJsChunks(code);
  if (nextjs.length > 0) {
    nextjs.forEach(p => console.log(`  /${p.path}`));
  } else {
    console.log(`  No Next.js pages detected`);
  }

  console.log(`\n[8] Absolute JS URLs Embedded`);
  console.log(`  ${'-'.repeat(50)}`);
  const urls = extractAllJsUrls(code);
  if (urls.length > 0) {
    urls.forEach(u => console.log(`  ${u}`));
  } else {
    console.log(`  None found`);
  }

  console.log(`\n[9] Build Metadata`);
  console.log(`  ${'-'.repeat(50)}`);
  const bm = extractBuildMetadata(code);
  const keys = Object.keys(bm);
  if (keys.length > 0) {
    keys.forEach(k => console.log(`  ${k}: ${bm[k]}`));
  } else { console.log(`  No build metadata embedded`); }

  console.log(`\n[10] Entry Point Reconstruction`);
  console.log(`  ${'-'.repeat(50)}`);
  const ep = extractEntryPoints(code);
  if (ep.length > 0) {
    ep.forEach(e => console.log(`  ${e.name}: ${e.path}`));
  } else { console.log(`  Could not determine entry points`); }

  console.log(`\n[11] Module Dependency Graph`);
  console.log(`  ${'-'.repeat(50)}`);
  const dg = extractDependencyGraph(code);
  console.log(`  Total dependency edges: ${dg.edges}`);
  if (dg.hubs.length > 0) {
    console.log(`  Most-referenced modules (hubs):`);
    dg.hubs.forEach(h => console.log(`    [${h.references}x] ${h.module}`));
  }

  console.log(`\n[12] Circular Dependency Scan`);
  console.log(`  ${'-'.repeat(50)}`);
  const cd = detectCircularDeps(code);
  if (cd.warnings.length > 0) { cd.warnings.forEach(w => console.log(`  ${w}`)); }
  console.log(`  Module IDs referenced: ${cd.moduleRefCount}`);

  console.log(`\n[13] Vendor Library Fingerprinting`);
  console.log(`  ${'-'.repeat(50)}`);
  const vf = fingerprintVendors(code);
  if (vf.length > 0) {
    vf.forEach(v => console.log(`  ${v}`));
  } else { console.log(`  No known vendor libraries detected`); }

  console.log(`\n[14] Code Splitting Strategy Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  const cs = analyzeCodeSplitting(code);
  if (cs.strategies.length > 0) {
    cs.strategies.forEach(s => console.log(`  Strategy: ${s}`));
  }
  if (cs.chunkGroups) {
    console.log(`  Lazy imports: ${cs.chunkGroups.lazy}, Eager requires: ${cs.chunkGroups.eager}`);
  }

  console.log(`\n[15] Async Boundary Detection`);
  console.log(`  ${'-'.repeat(50)}`);
  const ab = detectAsyncBoundaries(code);
  if (ab.length > 0) {
    ab.forEach(a => console.log(`  ${a.type}: ${a.count}`));
  } else { console.log(`  No async boundaries detected`); }

  console.log(`\n[16] Webpack Plugin Fingerprinting`);
  console.log(`  ${'-'.repeat(50)}`);
  const wp = detectWebpackPlugins(code);
  if (wp.length > 0) {
    wp.forEach(p => console.log(`  ${p}`));
  } else { console.log(`  No specific webpack plugins identified`); }

  console.log(`\n[17] Module Concatenation / Scope Hoisting`);
  console.log(`  ${'-'.repeat(50)}`);
  const mh = detectConcatScopeHoisting(code);
  if (mh.length > 0) {
    mh.forEach(m => console.log(`  ${m.type}: ${m.count || m.detail}`));
  } else { console.log(`  No module concatenation detected`); }

  console.log(`\n[18] Bundle Budget Analysis`);
  console.log(`  ${'-'.repeat(50)}`);
  const bb = analyzeBundleBudget(code);
  console.log(`  Size: ${bb.totalChars} chars / ${bb.totalLines} lines`);
  console.log(`  Avg line: ${bb.avgLineLen} chars, Max line: ${bb.maxLineLen} chars`);
  console.log(`  Functions: ${bb.functions}, Variables: ${bb.variables}`);
  console.log(`  Comments: ${bb.comments}, Empty lines: ${bb.emptyLines}`);
  console.log(`  Function density: ${bb.density} func/line`);

  console.log(`\n${'='.repeat(70)}`);
  console.log(`  Analysis complete`);
  console.log(`${'='.repeat(70)}\n`);
}

const args = process.argv.slice(2);
if (args.length === 0) {
  console.log(`Usage: node webpack-chunk-extractor.js <input.js>`);
  console.log(`       node webpack-chunk-extractor.js <directory>`);
  process.exit(1);
}

const inputPath = args[0];
if (fs.statSync(inputPath).isDirectory()) {
  const files = fs.readdirSync(inputPath).filter(f => f.endsWith('.js'));
  files.forEach(f => analyze(path.join(inputPath, f)));
} else {
  analyze(inputPath);
}
