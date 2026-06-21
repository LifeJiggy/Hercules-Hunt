const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node csp-bypass-analyzer.js <file.js>'); process.exit(1); }

const loaded = harden.safeLoadFile(args[0]);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
const code = loaded.content;

const CSP_BYPASS_GADGETS = [
  { name: 'JSONP endpoint usage', re: /src\s*=\s*["'][^"']*callback[=?#]/gi, risk: 'JSONP callbacks bypass script-src', severity: 'HIGH' },
  { name: 'CDN library without SRI', re: /src\s*=\s*["']https?:\/\/(?:cdnjs|unpkg|cdn\.jsdelivr|cdn\.cloudflare)\.com[^"']*["']/gi, risk: 'CDN script without integrity attribute — supply chain bypass', severity: 'HIGH' },
  { name: 'CDN with hash only', re: /integrity\s*=\s*["']sha[^"']+["']/gi, risk: 'Weak hash algo — SHA1/SHA256 vs SHA384', severity: 'MEDIUM' },
  { name: 'Angular Trusted Types bypass', re: /bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustUrl/gi, risk: 'Angular trusted type bypass — CSP doesnt apply', severity: 'CRITICAL' },
  { name: 'nonce reuse pattern', re: /nonce\s*=\s*["']([^"']+)["'][^>]*><\/script>/gi, risk: 'Hardcoded nonce reused across scripts — defeats CSP', severity: 'HIGH' },
  { name: 'script-src-attr bypass (inline)', re: /onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=/gi, risk: 'Inline event handlers bypass script-src, only script-src-attr controls these', severity: 'HIGH' },
  { name: 'base-uri not restricted', re: /<base\s+href\s*=/gi, risk: 'base tag injection redirects relative script loads', severity: 'MEDIUM' },
  { name: 'importScripts in worker', re: /importScripts\s*\([^)]+/gi, risk: 'Web Worker importScripts bypasses CSP', severity: 'MEDIUM' },
  { name: 'eval in worker', re: /Worker\s*\([^)]*blob:/gi, risk: 'blob: worker URL bypasses script-src', severity: 'HIGH' },
  { name: 'dangling markup injection', re: /<[a-z]+[^>]*action\s*=\s*["']https?:\/\/[^"']+/gi, risk: 'Form action to attacker — CSP dont block form actions by default', severity: 'MEDIUM' },
  { name: 'window.open CSP bypass', re: /window\.open\s*\([^)]*["'](?:javascript|data):/gi, risk: 'javascript: URI in window.open bypasses script-src', severity: 'HIGH' },
  { name: 'import() dynamic import bypass', re: /import\s*\(\s*["'](?:https?:|\/\/)/gi, risk: 'Dynamic import with absolute URL — bypasses script-src if CDN in allowlist', severity: 'MEDIUM' },
  { name: 'CSP report-uri/report-to', re: /report-uri|report-to|report_uri/i, risk: 'CSP violation endpoint found — check if endpoint accepts arbitrary data', severity: 'LOW' },
  { name: 'frame-src / object-src missing', re: /<embed\s|<object\s|<applet\s/gi, risk: 'Plugin content may bypass page CSP if object-src not restricted', severity: 'MEDIUM' },
  { name: 'CSS injection (style-src bypass)', re: /<link\s+[^>]*href\s*=\s*["']https?:\/\/[^"']+/gi, risk: 'External stylesheet — style-src-attr bypass via CSS', severity: 'MEDIUM' },
];

function extractCSPFromHTML(code) {
  const cspMeta = code.match(/<meta[^>]*http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*["']([^"']+)["']/i);
  const cspHeader = code.match(/(?:Content-Security-Policy|Content-Security-Policy-Report-Only)[:\s]+([^"\n\r;]+(?:;[^"\n\r;]+)*)/gi);
  return { meta: cspMeta ? cspMeta[1] : null, header: cspHeader ? cspHeader[0] : null };
}

const findings = [];
for (const gadget of CSP_BYPASS_GADGETS) {
  gadget.re.lastIndex = 0;
  let m;
  while ((m = gadget.re.exec(code)) !== null) {
    const line = code.substring(0, m.index).split('\n').length;
    findings.push({ gadget: gadget.name, line, severity: gadget.severity, risk: gadget.risk, match: m[0].substring(0, 100) });
  }
}

const csp = extractCSPFromHTML(code);

console.log(`\n========================================`);
console.log(`  CSP Bypass Analysis`);
console.log(`========================================`);

if (csp.meta) { console.log(`  CSP (meta tag):  ${csp.meta.substring(0, 120)}`); }
if (csp.header) { console.log(`  CSP (header):    ${csp.header.substring(0, 120)}`); }
if (!csp.meta && !csp.header) { console.log(`  No CSP policy found in this bundle.`); }
console.log(`  Bypass gadgets:  ${findings.length}`);
console.log('');

if (findings.length === 0) { console.log('  No CSP bypass gadgets detected.\n'); process.exit(0); }

const bySev = {};
for (const f of findings) { bySev[f.severity] = (bySev[f.severity] || 0) + 1; }
console.log('  By severity:');
Object.entries(bySev).forEach(([s, c]) => console.log(`    ${harden.colorize(s)}: ${c}`));
console.log('');

const grouped = {};
for (const f of findings) {
  if (!grouped[f.gadget]) grouped[f.gadget] = [];
  grouped[f.gadget].push(f);
}
console.log('  Gadgets found:');
Object.entries(grouped).sort((a, b) => b[1].length - a[1].length).forEach(([gadget, items]) => {
  const maxSev = items.reduce((a, b) => a.severity === 'CRITICAL' ? a : b);
  console.log(`    ${harden.colorize(maxSev.severity)} ${gadget.padEnd(35)}: ${items.length}`);
  items.slice(0, 1).forEach(f => console.log(`      Ln ${f.line}: ${f.match.substring(0, 80)}`));
});
console.log('');

if (!csp.meta && !csp.header) {
  console.log('  [!] No CSP found — all gadgets are exploitable if CSP is missing.');
  console.log('      Prioritize script injection gadgets for XSS chains.');
  console.log('');
}

module.exports = { CSP_BYPASS_GADGETS };
