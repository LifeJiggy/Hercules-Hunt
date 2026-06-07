const readline = require('readline');
const { BrowserAutomation, DOMManipulation, UserFunctionalities, Parameters, APIFuzzer, TokenAnalyzer, EndpointCollector, SessionHijacker, XSSHunter, CSRFTester, PrototypePollution, PostMessageExplorer, StorageAuditor, EventInspector, ClientSideScanner } = require('./index');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function ask(question) {
  return new Promise(resolve => rl.question(question, resolve));
}

function color(text, code = 36) { return `\x1b[${code}m${text}\x1b[0m`; }

const menu = `
${color('╔══════════════════════════════════════════════╗', 35)}
${color('║    Hercules-Hunt Client-Side Hunting Toolkit    ║', 35)}
${color('╚══════════════════════════════════════════════╝', 35)}

${color('── General Tools ──', 37)}
${color('1.', 33)}  ${color('browser-automation', 36)}     — Playwright browser automation
${color('2.', 33)}  ${color('dom-manipulation', 36)}       — DOM querying & injection
${color('3.', 33)}  ${color('user-functionalities', 36)}   — Login/register/multi-account
${color('4.', 33)}  ${color('parameters', 36)}             — Parameter extraction & fuzzing
${color('5.', 33)}  ${color('api-fuzzer', 36)}             — HTTP method/header/rate fuzzing
${color('6.', 33)}  ${color('token-analyzer', 36)}         — JWT decode & attacks
${color('7.', 33)}  ${color('endpoint-collector', 36)}     — JS bundle endpoint extraction

${color('── P1 Client-Side Hunter Tools ──', 31)}
${color('8.', 33)}  ${color('session-hijacker', 36)}       — Cookie audit, fixation, entropy
${color('9.', 33)}  ${color('xss-hunter', 36)}             — DOM/reflected/stored XSS, mXSS
${color('10.', 33)} ${color('csrf-tester', 36)}            — CSRF tokens, SameSite, CORS
${color('11.', 33)} ${color('prototype-pollution', 36)}    — Prototype pollution & gadgets
${color('12.', 33)} ${color('postmessage-explorer', 36)}   — postMessage listeners & chains
${color('13.', 33)} ${color('storage-auditor', 36)}        — Client-side storage & secrets
${color('14.', 33)} ${color('event-inspector', 36)}        — Events, clickjacking, UI redress
${color('15.', 33)} ${color('client-side-scanner', 35)}    — FULL SCAN (all tools, report)

${color('0.', 33)}  ${color('Exit', 31)}
`;

const toolActions = {
  async 'browser-automation'() {
    const url = await ask(color('  Enter URL: ', 33));
    const ba = new BrowserAutomation({ headless: false });
    await ba.launch(); await ba.navigate(url);
    console.log(color(`  [✓] Page loaded`, 32));
    const action = await ask(color('  [s]creenshot [l]inks [f]orms [c]ookies [q]uit: ', 33));
    if (action === 's') console.log(color(`  [✓] ${await ba.screenshot('capture_' + Date.now())}`, 32));
    else if (action === 'l') (await ba.extractLinks()).slice(0, 20).forEach(l => console.log(`    ${l}`));
    else if (action === 'f') (await ba.extractForms()).forEach(f => console.log(`    ${f.method} ${f.action} (${f.fields.length}f)`));
    else if (action === 'c') (await ba.extractCookies()).forEach(c => console.log(`    ${c.name}=${c.value}`));
    await ba.close();
  },
  async 'dom-manipulation'() {
    const url = await ask(color('  URL: ', 33));
    const selector = await ask(color('  CSS selector: ', 33));
    const ba = new BrowserAutomation({ headless: true });
    await ba.launch(); await ba.navigate(url);
    const dom = new DOMManipulation(ba.page);
    const r = await dom.querySelector(selector);
    if (r) { console.log(color(`  [✓] <${r.tag}>`, 32)); console.log(`    Text: ${(r.text || '').slice(0, 100)}`); }
    else console.log(color('  [✗] Not found', 31));
    if (await ask(color('  Show inputs? (y/n): ', 33)) === 'y') (await dom.findInputs()).forEach(i => console.log(`    ${i.name} (${i.type})`));
    if (await ask(color('  Show localStorage? (y/n): ', 33)) === 'y') Object.entries(await dom.getLocalStorage()).forEach(([k, v]) => console.log(`    ${k}: ${(v || '').slice(0, 100)}`));
    await ba.close();
  },
  async 'user-functionalities'() {
    const ba = new BrowserAutomation({ headless: false }); await ba.launch();
    const uf = new UserFunctionalities(ba.page);
    const mode = await ask(color('  [l]ogin [r]egister [c]apture-session: ', 33));
    if (mode === 'l') {
      const s = await uf.login({
        url: await ask(color('  Login URL: ', 33)), usernameField: await ask(color('  Username field: ', 33)),
        passwordField: await ask(color('  Password field: ', 33)), submitButton: await ask(color('  Submit: ', 33)),
        username: await ask(color('  Username: ', 33)), password: await ask(color('  Password: ', 33))
      });
      console.log(color(`  [✓] Logged in. ${s.cookies.length} cookies`, 32));
    } else if (mode === 'c') { await uf.saveSession('saved_' + Date.now()); console.log(color('  [✓] Saved', 32)); }
    await ba.close();
  },
  async 'parameters'() {
    const p = new Parameters();
    const mode = await ask(color('  [e]xtract [m]utate [p]ollution [f]uzz-names: ', 33));
    if (mode === 'e') {
      const r = p.extractFromUrl(await ask(color('  URL: ', 33))); console.log(color(`  ${r.paramCount} params`, 36));
      Object.entries(r.params).forEach(([k, v]) => console.log(`    ${k} = ${v}`));
    } else if (mode === 'm') {
      const extracted = p.extractFromUrl(await ask(color('  URL: ', 33)));
      const mutations = p.generateMutationSet(extracted.params, await ask(color('  Type (idor,sqli,xss,ssrf,lfi,ssti): ', 33)));
      mutations.slice(0, 10).forEach(m => console.log(`    ${m.param}=${m.value}`));
    }
  },
  async 'api-fuzzer'() {
    const fuzzer = new APIFuzzer();
    const endpoint = await ask(color('  Endpoint: ', 33));
    const mode = await ask(color('  [m]ethod [h]eader [r]ate-limit [s]can: ', 33));
    if (mode === 's' || mode === 'm') {
      if (mode === 's') { const r = await fuzzer.scan(endpoint); console.log(`  Baseline: ${r.baseline.status} | Methods: ${r.summary.alternateMethods.join(', ') || 'none'}`); }
      else (await fuzzer.fuzzMethod(endpoint)).forEach(r => console.log(`  ${r.allowed ? '✓' : '✗'} ${r.method} → ${r.status}`));
    } else if (mode === 'h') (await fuzzer.fuzzHeaders(endpoint)).filter(r => r.interesting).forEach(r => console.log(`  ${r.header}: ${r.value} → ${r.status}`));
    else if (mode === 'r') {
      const r = await fuzzer.fuzzRateLimit(endpoint, parseInt(await ask(color('  Requests: ', 33)) || '50'));
      console.log(`  ${r.totalRequests} req in ${r.elapsed}ms | Rate-limited: ${r.rateLimitDetected ? color('YES', 31) : color('NO', 32)}`);
    }
  },
  async 'token-analyzer'() {
    const ta = new TokenAnalyzer();
    const token = await ask(color('  JWT: ', 33));
    const d = ta.decodeJWT(token);
    if (!d.valid) return console.log(color('  Invalid JWT', 31));
    console.log(`  Alg: ${d.algorithm} | Issuer: ${d.issuer || '-'} | Exp: ${d.expiration || '-'}`);
    if (d.algorithm === 'none') console.log(color('  [!] ALG=NONE — CRITICAL', 31));
    if (await ask(color('  Test alg=none? (y/n): ', 33)) === 'y') (await ta.testAlgNone(token)).tests.forEach(t => console.log(`    ${t.name}: ${t.token.slice(0, 50)}...`));
  },
  async 'endpoint-collector'() {
    const ec = new EndpointCollector();
    const mode = await ask(color('  [u]rl [s]cript [b]undle: ', 33));
    if (mode === 'u' || mode === 'b') {
      const r = await (mode === 'u' ? ec.analyzeScript(await ask(color('  JS URL: ', 33))) : ec.recursiveCrawlJS(await ask(color('  Bundle URL: ', 33)), parseInt(await ask(color('  Depth (0-2): ', 33)) || '0')));
      const items = mode === 'u' ? [r] : r;
      items.forEach(i => console.log(`  ${i.url} — ${i.endpointsFound || 0} endpoints, ${i.secretsFound || 0} secrets`));
      console.log(color(`  [✓] ${ec.exportResults('md')}`, 32));
    } else {
      const r = await ec.discoverScripts(await ask(color('  Page URL: ', 33)));
      console.log(`  ${r.scripts.length} scripts`); r.scripts.slice(0, 10).forEach(s => console.log(`    ${s.src}`));
    }
  },
  async 'session-hijacker'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch(); await ba.navigate(url);
    const sh = new SessionHijacker(ba.page);
    const results = await sh.fullSessionAudit(url);
    results.prioritized.forEach(f => console.log(`  [${color(f.severity === 'CRITICAL' || f.severity === 'HIGH' ? '!' : 'i', f.severity === 'CRITICAL' ? 31 : 33)}] ${f.issue || f.name}: ${f.issue || ''}`));
    console.log(color(`  Total: ${results.totalFindings} findings`, 36));
    await ba.close();
  },
  async 'xss-hunter'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch(); await ba.navigate(url);
    const xss = new XSSHunter(ba.page);
    const r = await xss.fullScan(url);
    console.log(`  DOM sinks: ${r.domSinks.length} | CSP: ${r.csp?.csp ? 'found' : 'none'}`);
    r.domSinks.slice(0, 10).forEach(s => console.log(`    ${s.sink} @ line ${s.line}: ${s.code.slice(0, 80)}`));
    if (await ask(color('  Test reflected XSS on a parameter? (y/n): ', 33)) === 'y') {
      const testUrl = await ask(color('  URL with param (e.g. ?q=test): ', 33));
      const param = await ask(color('  Parameter name: ', 33));
      const findings = await xss.testReflectedXSS(testUrl, param);
      findings.forEach(f => console.log(`  [${color('!', 31)}] Reflected: ${f.payload}`));
    }
    await ba.close();
  },
  async 'csrf-tester'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch(); await ba.navigate(url);
    const csrf = new CSRFTester(ba.page);
    const r = await csrf.fullScan(url);
    console.log(`  Token issues: ${r.tokenStrength.findings.length} | SameSite issues: ${r.sameSite.findings.length}`);
    r.tokenStrength.findings.forEach(f => console.log(`  [${f.severity === 'CRITICAL' ? color('!', 31) : color('i', 33)}] ${f.issue}`));
    r.sameSite.findings.forEach(f => console.log(`  [i] ${f.issue}`));
    if (r.jsonp.length) console.log(color(`  [!] ${r.jsonp.length} JSONP endpoints`, 33));
    await ba.close();
  },
  async 'prototype-pollution'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch(); await ba.navigate(url);
    const pp = new PrototypePollution(ba.page);
    const r = await pp.testAllVectors();
    console.log(`  Basic pollution: ${r.basicPollution.vulnerable ? color('VULNERABLE', 31) : color('safe', 32)}`);
    for (const [lib, vuln] of Object.entries(r.libraryPollution)) console.log(`  ${lib}: ${vuln ? color('VULNERABLE', 31) : color('safe', 32)}`);
    const clobber = Object.keys(r.domClobbering);
    if (clobber.length) console.log(color(`  DOM clobbering: ${clobber.length} elements found`, 33));
    if (r.scriptGadgets.length) console.log(color(`  Gadgets: ${r.scriptGadgets.length} found`, 31));
    await ba.close();
  },
  async 'postmessage-explorer'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch();
    const pm = new PostMessageExplorer(ba.page);
    const r = await pm.fullScan(url);
    console.log(`  Listeners: ${r.listenerCount} | Iframes: ${r.iframeCount}`);
    if (r.originValidation.length) r.originValidation.forEach(f => console.log(color(`  [!] ${f.issue}`, 31)));
    if (r.wildcardPostMessage.length) console.log(color(`  [!] ${r.wildcardPostMessage.length} wildcard postMessage(s)`, 31));
    if (r.windowOpener.length) console.log(color(`  [!] ${r.windowOpener.length} vulnerable opener(s)`, 33));
    if (r.xssChain.length) console.log(color(`  [!] ${r.xssChain.length} postMessage→XSS chain(s)`, 31));
    await ba.close();
  },
  async 'storage-auditor'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch(); await ba.navigate(url);
    const sa = new StorageAuditor(ba.page);
    const r = await sa.fullAudit();
    console.log(`  localStorage: ${r.summary.localStorageKeys} keys`);
    console.log(`  sessionStorage: ${r.summary.sessionStorageKeys} keys`);
    console.log(`  Cookies: ${r.summary.cookies}`);
    console.log(`  IndexedDB: ${r.summary.indexedDBDatabases} databases`);
    console.log(`  Cache API: ${r.summary.cacheAPICaches} caches`);
    console.log(`  Service Worker: ${r.summary.serviceWorker ? 'registered' : 'none'}`);
    if (r.sensitiveData.localStorage.length) r.sensitiveData.localStorage.forEach(f => console.log(color(`  [${f.severity === 'CRITICAL' ? '!' : 'i'}] LS: ${f.type}: ${f.value}`, f.severity === 'CRITICAL' ? 31 : 33)));
    if (r.sensitiveData.sessionStorage.length) r.sensitiveData.sessionStorage.forEach(f => console.log(color(`  [${f.severity === 'CRITICAL' ? '!' : 'i'}] SS: ${f.type}: ${f.value}`, f.severity === 'CRITICAL' ? 31 : 33)));
    if (r.sensitiveData.cookies.length) r.sensitiveData.cookies.forEach(f => console.log(color(`  [${f.severity === 'CRITICAL' ? '!' : 'i'}] Cookie: ${f.cookie} — ${f.issue}`, f.severity === 'CRITICAL' ? 31 : 33)));
    if (r.remnants.length) r.remnants.forEach(f => console.log(`  Remnant: ${f.type} (${f.count || 1})`));
    await ba.close();
  },
  async 'event-inspector'() {
    const url = await ask(color('  URL: ', 33));
    const ba = new BrowserAutomation({ headless: true }); await ba.launch();
    const ei = new EventInspector(ba.page);
    const r = await ei.fullScan(url);
    console.log(`  Event listeners: ${r.eventListeners.length}`);
    console.log(`  Clickjacking: ${r.clickjacking.vulnerable ? color('VULNERABLE', 31) : color('protected', 32)}`);
    if (r.keyboardCapture.length) console.log(color(`  [!] ${r.keyboardCapture.length} keyboard capture(s)`, 31));
    if (r.uiRedressing.length) console.log(color(`  [!] ${r.uiRedressing.length} UI redress element(s)`, 33));
    r.eventListeners.slice(0, 15).forEach(l => console.log(`    ${l.element} → ${l.event} (${l.handlerCount || 'inline'})`));
    await ba.close();
  },
  async 'client-side-scanner'() {
    const url = await ask(color('  Target URL: ', 33));
    const headless = await ask(color('  Headless mode? (y/n): ', 33)) === 'y';
    const scanner = new ClientSideScanner({ headless });
    await scanner.scan(url);
  }
};

async function main() {
  console.log(menu);
  let running = true;
  while (running) {
    const choice = await ask(color('  Select tool (0-15): ', 35));
    const toolNames = ['', 'browser-automation', 'dom-manipulation', 'user-functionalities', 'parameters', 'api-fuzzer', 'token-analyzer', 'endpoint-collector', 'session-hijacker', 'xss-hunter', 'csrf-tester', 'prototype-pollution', 'postmessage-explorer', 'storage-auditor', 'event-inspector', 'client-side-scanner'];
    if (choice === '0') { running = false; break; }
    const toolName = toolNames[parseInt(choice)];
    if (toolName && toolActions[toolName]) {
      try { await toolActions[toolName](); }
      catch (e) { console.log(color(`  [✗] Error: ${e.message}`, 31)); }
    } else { console.log(color('  Invalid choice.', 31)); }
    console.log('');
    if (await ask(color('  Run another tool? (y/n): ', 33)) !== 'y') running = false;
  }
  rl.close();
  console.log(color('\n  Goodbye!', 35));
}

if (require.main === module) main().catch(console.error);

module.exports = { main, menu, toolActions };
