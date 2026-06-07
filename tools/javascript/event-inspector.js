class EventInspector {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  async enumerateEventListeners() {
    return this.page.evaluate(() => {
      const results = [];
      const allElements = document.querySelectorAll('*');
      allElements.forEach(el => {
        const tag = el.tagName.toLowerCase();
        const id = el.id;
        const className = el.className?.slice(0, 50);
        const listeners = getEventListeners?.(el);
        if (listeners && Object.keys(listeners).length) {
          Object.entries(listeners).forEach(([event, handlers]) => {
            results.push({
              element: `${tag}${id ? '#' + id : ''}${className ? '.' + className : ''}`,
              event,
              handlerCount: handlers.length,
              handlerTypes: handlers.map(h => h.type || 'unknown')
            });
          });
        }
      });
      if (results.length === 0) {
        document.querySelectorAll('*').forEach(el => {
          const attrs = el.attributes;
          for (let i = 0; i < attrs.length; i++) {
            if (attrs[i].name.startsWith('on')) {
              results.push({
                element: `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}`,
                event: attrs[i].name,
                inline: true,
                code: attrs[i].value.slice(0, 100)
              });
            }
          }
        });
      }
      return results.slice(0, 100);
    }).catch(() => []);
  }

  async detectClickjacking() {
    const results = { vulnerable: false, protections: [], issues: [] };
    const headers = await this.page.evaluate(async () => {
      const resp = await fetch(window.location.href);
      return {
        xfo: resp.headers.get('X-Frame-Options'),
        csp: resp.headers.get('Content-Security-Policy')
      };
    });
    if (headers.xfo) results.protections.push(`X-Frame-Options: ${headers.xfo}`);
    if (headers.csp && headers.csp.includes('frame-ancestors')) {
      const match = headers.csp.match(/frame-ancestors\s+([^;]+)/);
      if (match) results.protections.push(`CSP frame-ancestors: ${match[1]}`);
    }
    if (!headers.xfo && (!headers.csp || !headers.csp.includes('frame-ancestors'))) {
      results.vulnerable = true;
      results.issues.push('No X-Frame-Options or CSP frame-ancestors — vulnerable to clickjacking');
      this.findings.push({ type: 'clickjacking', severity: 'HIGH', detail: 'No framing protections detected' });
    }
    const metaFrame = await this.page.evaluate(() => {
      const meta = document.querySelector('meta[http-equiv="X-Frame-Options"]');
      return meta ? meta.getAttribute('content') : null;
    });
    if (metaFrame) {
      results.protections.push(`Meta X-Frame-Options: ${metaFrame}`);
      results.vulnerable = false;
    }
    return results;
  }

  async testFrameBusting() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('top !== self') || code.includes('top != self') || code.includes('top.location') || code.includes('parent.location') || code.includes('self !== top')) {
          findings.push({ type: 'frame-busting', code: code.slice(0, 200), src: s.src || 'inline' });
        }
      });
      return findings;
    });
  }

  async detectUIRedressing() {
    return this.page.evaluate(() => {
      const results = [];
      const transparent = document.querySelectorAll('iframe[style*="opacity"], iframe[style*="transparent"]');
      transparent.forEach(iframe => {
        results.push({ type: 'transparent-iframe', src: iframe.src, style: iframe.getAttribute('style') });
      });
      const overlapping = document.querySelectorAll('iframe[style*="position"], iframe[style*="absolute"]');
      overlapping.forEach(iframe => {
        results.push({ type: 'overlapping-iframe', src: iframe.src, style: iframe.getAttribute('style') });
      });
      const buttons = document.querySelectorAll('button, [role="button"], input[type="submit"], a.btn');
      buttons.forEach(btn => {
        const style = window.getComputedStyle(btn);
        if (style.opacity < 0.1 || style.display === 'none' || style.visibility === 'hidden') {
          results.push({ type: 'hidden-overlay', element: `${btn.tagName}${btn.id ? '#' + btn.id : ''}`, style: `opacity:${style.opacity}` });
        }
      });
      return results;
    });
  }

  async testKeyboardCapture() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('keydown') || code.includes('keyup') || code.includes('keypress')) {
          if (code.includes('password') || code.includes('input') || code.includes('value')) {
            findings.push({ type: 'keyboard-capture', snippet: code.slice(0, 200), src: s.src || 'inline' });
          }
        }
      });
      return findings;
    });
  }

  async testMouseEventCapture() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if ((code.includes('mousedown') || code.includes('mouseup') || code.includes('click') || code.includes('mousemove')) && (code.includes('offsetX') || code.includes('offsetY') || code.includes('clientX') || code.includes('clientY'))) {
          findings.push({ type: 'mouse-capture', snippet: code.slice(0, 200), src: s.src || 'inline' });
        }
      });
      return findings;
    });
  }

  async testEventTiming() {
    const results = [];
    for (let i = 0; i < 5; i++) {
      const start = Date.now();
      await this.page.evaluate(() => {
        return new Promise(resolve => {
          const btn = document.createElement('button');
          btn.onclick = () => resolve();
          btn.click();
        });
      });
      results.push(Date.now() - start);
    }
    return { timings: results };
  }

  async detectDragAndDropIssues() {
    return this.page.evaluate(() => {
      const scripts = document.querySelectorAll('script');
      const findings = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        if (code.includes('draggable') || code.includes('ondrop') || code.includes('ondragover') || code.includes('ondragstart')) {
          findings.push({ type: 'drag-drop', snippet: code.slice(0, 200), src: s.src || 'inline' });
        }
      });
      return findings;
    });
  }

  async fullScan(url) {
    console.log('[EventInspector] Scanning event surface...');
    await this.page.goto(url, { waitUntil: 'networkidle' });
    const results = {
      eventListeners: await this.enumerateEventListeners(),
      clickjacking: await this.detectClickjacking(),
      frameBusting: await this.testFrameBusting(),
      uiRedressing: await this.detectUIRedressing(),
      keyboardCapture: await this.testKeyboardCapture(),
      mouseCapture: await this.testMouseEventCapture(),
      dragDrop: await this.detectDragAndDropIssues()
    };
    if (results.clickjacking.vulnerable) this.findings.push({ type: 'clickjacking', severity: 'HIGH', detail: 'Page can be framed — clickjacking/UI redress attack surface' });
    if (results.keyboardCapture.length) this.findings.push({ type: 'keyboard-capture', count: results.keyboardCapture.length, severity: 'HIGH' });
    if (results.uiRedressing.length) this.findings.push({ type: 'ui-redressing', count: results.uiRedressing.length, severity: 'MEDIUM' });
    if (results.mouseCapture.length) this.findings.push({ type: 'mouse-capture', count: results.mouseCapture.length, severity: 'LOW' });
    return results;
  }
}

module.exports = { EventInspector };
