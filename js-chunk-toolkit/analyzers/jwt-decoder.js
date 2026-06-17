const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node jwt-decoder.js <file_or_dir>'); process.exit(1); }

function load(p) {
  if (fs.statSync(p).isDirectory()) {
    return fs.readdirSync(p).filter(f => /\.(js|mjs|cjs|map)$/.test(f))
      .flatMap(f => ({ name: f, content: fs.readFileSync(path.join(p, f), 'utf-8') }));
  }
  return [{ name: path.basename(p), content: fs.readFileSync(p, 'utf-8') }];
}

const files = load(args[0]);
const found = [];

files.forEach(({ name, content }) => {
  const jwtRe = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  let match;
  while ((match = jwtRe.exec(content)) !== null) {
    try {
      const parts = match[0].split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      const exp = payload.exp ? new Date(payload.exp * 1000).toISOString() : 'none';
      const expired = payload.exp ? (payload.exp * 1000 < Date.now() ? 'EXPIRED' : 'valid') : 'unknown';
      found.push({
        file: name, token: match[0], header, payload,
        algorithm: header.alg || 'unknown', type: header.typ || 'JWT',
        issuer: payload.iss || 'unknown', subject: payload.sub || 'unknown',
        expiry: exp, status: expired, claims: Object.keys(payload),
      });
    } catch (e) {}
  }
});

console.log(`\n${'='.repeat(70)}`);
console.log(`  JWT Decoder -- ${found.length} token(s) found in ${files.length} file(s)`);
console.log(`${'='.repeat(70)}`);

found.forEach((t, i) => {
  console.log(`\n[${i + 1}] ${t.file}`);
  console.log(`  Token: ${t.token.substring(0, 50)}...${t.token.substring(t.token.length - 20)}`);
  console.log(`  Status: ${t.status}`);
  console.log(`  Algorithm: ${t.algorithm}`);
  console.log(`  Type: ${t.type}`);
  console.log(`  Issuer: ${t.issuer}`);
  console.log(`  Subject: ${t.subject}`);
  console.log(`  Expiry: ${t.expiry}`);
  console.log(`  Claims: ${t.claims.join(', ')}`);
  console.log(`  Header: ${JSON.stringify(t.header)}`);
  console.log(`  Payload: ${JSON.stringify(t.payload, null, 4)}`);
});

if (found.length === 0) console.log('  No JWT tokens found.');

const weakAlgs = found.filter(t => ['none', 'None', 'NONE', 'HS256'].includes(t.algorithm));
if (weakAlgs.length > 0) {
  console.log(`\n[!] WARNING: ${weakAlgs.length} token(s) use potentially weak algorithms!`);
  weakAlgs.forEach(t => console.log(`    ${t.token.substring(0, 60)}... (${t.algorithm})`));
}

const expiredTokens = found.filter(t => t.status === 'EXPIRED');
if (expiredTokens.length > 0) {
  console.log(`\n[!] NOTE: ${expiredTokens.length} token(s) are expired.`);
}

console.log(`\n${'='.repeat(70)}\n`);
