class PostMessageExplorer {
  constructor(page) {
    this.page = page;
    this.findings = [];
    this.capturedMessages = [];
  }

  async enumerateListeners() {
    return this.page.evaluate(() => {
      const results = [];
      const iframes = document.querySelectorAll('iframe');
      iframes.forEach(iframe => { results.push({ type: 'iframe', src: iframe.src, id: iframe.id, name: iframe.name }); });
      const scripts = document.querySelectorAll('script');
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        const matches = code.match(/addEventListener\(['"]message['"]\s*,\s*(\w+)/g);
        if (matches) {
          matches.forEach(m => {
            const handlerName = m.match(/,\s*(\w+)/)[1];
            const handlerCode = code.match(new RegExp(`(?:function\\s+${handlerName}|var\\s+${handlerName}\\s*=|let\\s+${handlerName}\\s*=|const\\s+${handlerName}\\s*=)[^}]+}`));
            results.push({
              type: 'event-listener',
              handlerName,
              handlerCode: handlerCode ? handlerCode[0].slice(0, 500) : 'listener reference only',
              script: s.src || 'inline'
            });
          });
        }
      });
      return results;
    });
  }

  async captureMessages(durationMs = 5000) {
    this.capturedMessages = [];
    const page = this.page;
    const messages = this.capturedMessages;
    page.on('console', msg => {
      if (msg.type() === 'message' || msg.type() === 'info') {
        messages.push({ type: 'console', text: msg.text() });
      }
    });
    await page.evaluate(() => {
      const originalAddEventListener = window.addEventListener;
      window.addEventListener('message', function(event) {
        console.log('[PostMessageCapture] Origin: ' + event.origin + ' | Source: ' + (event.source?.location?.href || 'unknown') + ' | Data: ' + (typeof event.data === 'string' ? event.data : JSON.stringify(event.data)));
      });
    });
    await this.sleep(durationMs);
    return this.capturedMessages;
  }

  async testOriginValidation() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        const addEventListenerMatches = code.match(/addEventListener\(['"]message['"]/g);
        if (!addEventListenerMatches) return;
        const lines = code.split('\n');
        lines.forEach((line, idx) => {
          if (line.includes('addEventListener') && line.includes('message')) {
            const hasOriginCheck = /event\.origin\s*(===|==|!==|!=)/.test(code) || /\.origin\s*!==/.test(code) || /allowedOrigins/.test(code) || /whitelist/.test(code) || /trustedOrigins/.test(code);
            if (!hasOriginCheck) findings.push({ line: idx + 1, code: line.trim(), issue: 'No origin validation in postMessage listener' });
            else {
              if (/\*/.test(code.match(/event\.origin\s*===\s*['"]([^'"]+)['"]/)?.[1] || '')) findings.push({ line: idx + 1, code: line.trim(), issue: 'Wildcard origin validation' });
              if (/\.indexOf\(/.test(code) && !/===/.test(code)) findings.push({ line: idx + 1, issue: 'origin.indexOf() used instead of strict equality — bypassable' });
              if (/\.startsWith\(/.test(code) && !/===/.test(code)) findings.push({ line: idx + 1, issue: 'origin.startsWith() used — prefix matching bypassable' });
              if (/\.includes\(/.test(code) && !/===/.test(code)) findings.push({ line: idx + 1, issue: 'origin.includes() used — substring matching bypassable' });
            }
          }
        });
      });
      return findings;
    });
  }

  async testCrossOriginMessaging(targetOrigin) {
    const results = [];
    const testMessages = [
      JSON.stringify({ type: 'AUTH', token: 'FAKE_TOKEN_FOR_TEST' }),
      JSON.stringify({ type: 'LOGIN', username: 'admin', password: 'test' }),
      JSON.stringify({ type: 'EXEC', command: 'alert(1)' }),
      JSON.stringify({ type: 'REDIRECT', url: 'https://evil.com' }),
      JSON.stringify({ type: 'CHANGE_PASSWORD', newPassword: 'hacked!' }),
      JSON.stringify({ type: 'SETTINGS', isAdmin: true }),
      JSON.stringify({ type: 'EVAL', code: 'alert(document.cookie)' }),
      JSON.stringify({ key: '__proto__', value: { polluted: true } }),
      '__proto__',
      'constructor',
      JSON.stringify({ type: 'OPEN', url: 'https://evil.com/phish' }),
      JSON.stringify({ type: 'FETCH', url: 'https://evil.com/steal', method: 'GET' })
    ];
    for (const msg of testMessages) {
      try {
        await this.page.evaluate((msg) => {
          window.postMessage(msg, '*');
        }, msg);
        results.push({ message: msg.slice(0, 80), sent: true });
      } catch (e) { results.push({ message: msg.slice(0, 80), error: e.message }); }
    }
    return results;
  }

  async testWildcardPostMessage() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (code && code.includes('postMessage') && code.includes('*')) {
          const lines = code.split('\n');
          lines.forEach((line, idx) => {
            if (line.includes('postMessage') && line.includes('*') && !line.includes('//') && !line.includes('/*')) {
              findings.push({ line: idx + 1, code: line.trim() });
            }
          });
        }
      });
      return findings;
    });
  }

  async testWindowOpener() {
    return this.page.evaluate(() => {
      const links = document.querySelectorAll('a[target="_blank"]');
      const findings = [];
      links.forEach(link => {
        const rel = (link.getAttribute('rel') || '').toLowerCase();
        if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
          findings.push({ href: link.href, text: link.textContent?.slice(0, 50), issue: 'target="_blank" without rel="noopener" — window.opener abuse possible' });
        }
      });
      return findings;
    });
  }

  async postMessageToXSS() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('message') && (code.includes('innerHTML') || code.includes('outerHTML') || code.includes('document.write') || code.includes('eval(') || code.includes('setTimeout') || code.includes('setInterval'))) {
          const lines = code.split('\n');
          lines.forEach((line, idx) => {
            if ((line.includes('message') || line.includes('event.data')) && (line.includes('innerHTML') || line.includes('eval') || line.includes('document.write') || line.includes('Function('))) {
              findings.push({ line: idx + 1, code: line.trim(), issue: 'postMessage data used in DOM XSS sink' });
            }
          });
        }
      });
      return findings;
    });
  }

  async fullScan(url) {
    console.log('[PostMessageExplorer] Scanning postMessage surface...');
    await this.page.goto(url, { waitUntil: 'networkidle' });
    const results = {
      listeners: await this.enumerateListeners(),
      originValidation: await this.testOriginValidation(),
      wildcardPostMessage: await this.testWildcardPostMessage(),
      windowOpener: await this.testWindowOpener(),
      xssChain: await this.postMessageToXSS()
    };
    const iframeCount = results.listeners.filter(l => l.type === 'iframe').length;
    const listenerCount = results.listeners.filter(l => l.type === 'event-listener').length;
    if (results.originValidation.length) this.findings.push({ type: 'postmessage-origin-bypass', count: results.originValidation.length, severity: 'CRITICAL' });
    if (results.wildcardPostMessage.length) this.findings.push({ type: 'postmessage-wildcard', count: results.wildcardPostMessage.length, severity: 'HIGH' });
    if (results.windowOpener.length) this.findings.push({ type: 'window-opener', count: results.windowOpener.length, severity: 'MEDIUM' });
    if (results.xssChain.length) this.findings.push({ type: 'postmessage-xss-chain', count: results.xssChain.length, severity: 'CRITICAL' });
    if (listenerCount) this.findings.push({ type: 'postmessage-listeners', count: listenerCount, severity: 'INFO' });
    return { ...results, totalFindings: this.findings.length, iframeCount, listenerCount };
  }

  sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  async testChannelMessaging() {
    return this.page.evaluate(() => {
      const results = [];
      if (typeof BroadcastChannel !== 'undefined') {
        try { new BroadcastChannel('test'); results.push({ type: 'BroadcastChannel', available: true }); } catch { results.push({ type: 'BroadcastChannel', available: false }); }
      }
      if (typeof MessageChannel !== 'undefined') {
        try { const mc = new MessageChannel(); results.push({ type: 'MessageChannel', available: true }); } catch { results.push({ type: 'MessageChannel', available: false }); }
      }
      if (typeof SharedWorker !== 'undefined') results.push({ type: 'SharedWorker', available: true });
      return results;
    });
  }

  async detectCOOP() {
    return this.page.evaluate(async () => {
      try {
        const r = await fetch(window.location.href);
        const coop = r.headers.get('Cross-Origin-Opener-Policy');
        const coep = r.headers.get('Cross-Origin-Embedder-Policy');
        return { coop, coep };
      } catch { return {}; }
    });
  }

  async testSandboxedIframes() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('iframe').forEach(iframe => {
        const sandbox = iframe.getAttribute('sandbox') || '';
        const hasAllowScripts = sandbox.includes('allow-scripts');
        const hasAllowSameOrigin = sandbox.includes('allow-same-origin');
        if (hasAllowScripts && hasAllowSameOrigin) results.push({ src: iframe.src, sandbox, issue: 'allow-scripts + allow-same-origin = no sandbox — full access' });
        if (!sandbox) results.push({ src: iframe.src, issue: 'No sandbox attribute — full default access' });
      });
      return results;
    });
  }

  async testNestedIframeMessaging() {
    return this.page.evaluate(() => {
      const iframes = document.querySelectorAll('iframe');
      const results = [];
      iframes.forEach(f => {
        try {
          if (f.contentWindow) results.push({ src: f.src, accessible: true });
        } catch { results.push({ src: f.src, accessible: false }); }
      });
      return results;
    });
  }

  async testPopupOpenerChain() {
    return this.page.evaluate(() => {
      const links = document.querySelectorAll('a[target="_blank"]');
      return Array.from(links).map(l => ({ href: l.href, rel: l.getAttribute('rel'), hasNoOpener: (l.getAttribute('rel') || '').includes('noopener') }));
    });
  }

  async testOAuthRedirectURI() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        const matches = code.match(/redirect_uri["'\s:=]+["']([^"']+)["']/g);
        if (matches) matches.forEach(m => results.push({ redirect: m, src: s.src || 'inline' }));
      });
      return results;
    });
  }

  async testPostMessageToEval() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('addEventListener') && code.includes('message') && (code.includes('eval(') || code.includes('Function(') || code.includes('setTimeout') || code.includes('setInterval'))) {
          results.push({ type: 'postMessage→eval chain', src: s.src || 'inline', snippet: code.slice(0, 200) });
        }
      });
      return results;
    });
  }

  async testPostMessageToFetch() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('addEventListener') && code.includes('message') && (code.includes('fetch(') || code.includes('XMLHttpRequest') || code.includes('$.ajax') || code.includes('axios.'))) {
          results.push({ type: 'postMessage→fetch', src: s.src || 'inline', snippet: code.slice(0, 200) });
        }
      });
      return results;
    });
  }

  async testStructuredCloneBypass() {
    return this.page.evaluate(() => {
      try {
        const cloned = structuredClone({ data: '<img src=x onerror=alert(1)>' });
        return { bypass: cloned.data !== '<img src=x onerror=alert(1)>' };
      } catch { return { bypass: false }; }
    });
  }

  async testRestrictedURIMessaging() {
    const results = [];
    const uris = ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'file:///etc/passwd', 'blob:https://evil.com/test'];
    for (const uri of uris) {
      try {
        await this.page.evaluate((u) => { window.postMessage(u, '*'); }, uri);
        results.push({ uri: uri.slice(0, 50), blocked: false });
      } catch { results.push({ uri: uri.slice(0, 50), blocked: true }); }
    }
    return results;
  }

  async fullMessagingAudit(url) {
    console.log('[PostMessageExplorer] Full messaging audit...');
    await this.page.goto(url, { waitUntil: 'networkidle' });
    const results = {
      ...await this.fullScan(url),
      channelTypes: await this.testChannelMessaging(),
      coop: await this.detectCOOP(),
      sandboxAudit: await this.testSandboxedIframes(),
      nestedIframes: await this.testNestedIframeMessaging(),
      popupChain: await this.testPopupOpenerChain(),
      oauthRedirects: await this.testOAuthRedirectURI(),
      evalChain: await this.testPostMessageToEval(),
      fetchChain: await this.testPostMessageToFetch(),
      structuredClone: await this.testStructuredCloneBypass(),
      restrictedURIs: await this.testRestrictedURIMessaging()
    };
    return results;
  }
}

module.exports = { PostMessageExplorer };
