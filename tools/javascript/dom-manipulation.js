class DOMManipulation {
  constructor(page) {
    this.page = page;
  }

  async querySelector(selector) {
    return this.page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      return {
        tag: el.tagName,
        id: el.id,
        className: el.className,
        text: el.textContent?.slice(0, 200),
        html: el.innerHTML?.slice(0, 500),
        attributes: Array.from(el.attributes).map(a => ({ name: a.name, value: a.value })),
        rect: el.getBoundingClientRect()
      };
    }, selector);
  }

  async querySelectorAll(selector) {
    return this.page.evaluate((sel) => {
      return Array.from(document.querySelectorAll(sel)).map(el => ({
        tag: el.tagName,
        id: el.id,
        className: el.className,
        text: el.textContent?.slice(0, 200),
        attributes: Array.from(el.attributes).map(a => ({ name: a.name, value: a.value }))
      }));
    }, selector);
  }

  async findInputs() {
    return this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('input, textarea, select')).map(el => ({
        name: el.name,
        id: el.id,
        type: el.type || el.tagName.toLowerCase(),
        value: el.value,
        placeholder: el.placeholder,
        required: el.required,
        disabled: el.disabled,
        maxLength: el.maxLength,
        pattern: el.pattern,
        autocomplete: el.autocomplete
      }));
    });
  }

  async findHiddenInputs() {
    return this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('input[type="hidden"]')).map(el => ({
        name: el.name,
        value: el.value,
        id: el.id
      }));
    });
  }

  async findDataAttributes() {
    return this.page.evaluate(() => {
      const results = {};
      const all = document.querySelectorAll('*');
      all.forEach(el => {
        Array.from(el.attributes).forEach(attr => {
          if (attr.name.startsWith('data-')) {
            const key = attr.name;
            if (!results[key]) results[key] = new Set();
            results[key].add(attr.value);
          }
        });
      });
      const output = {};
      Object.keys(results).forEach(k => { output[k] = Array.from(results[k]); });
      return output;
    });
  }

  async injectElement(html, targetSelector = 'body') {
    return this.page.evaluate(({ html, targetSelector }) => {
      const target = document.querySelector(targetSelector);
      if (!target) throw new Error(`Target not found: ${targetSelector}`);
      const temp = document.createElement('div');
      temp.innerHTML = html;
      target.appendChild(temp.firstElementChild);
      return true;
    }, { html, targetSelector });
  }

  async removeElement(selector) {
    return this.page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      el.remove();
      return true;
    }, selector);
  }

  async setAttribute(selector, attr, value) {
    return this.page.evaluate(({ selector, attr, value }) => {
      const el = document.querySelector(selector);
      if (!el) return false;
      el.setAttribute(attr, value);
      return true;
    }, { selector, attr, value });
  }

  async removeAttribute(selector, attr) {
    return this.page.evaluate(({ selector, attr }) => {
      const el = document.querySelector(selector);
      if (!el) return false;
      el.removeAttribute(attr);
      return true;
    }, { selector, attr });
  }

  async simulateEvent(selector, eventType, options = {}) {
    return this.page.evaluate(({ selector, eventType, options }) => {
      const el = document.querySelector(selector);
      if (!el) throw new Error(`Element not found: ${selector}`);
      const event = new Event(eventType, { bubbles: true, cancelable: true, ...options });
      el.dispatchEvent(event);
      return true;
    }, { selector, eventType, options });
  }

  async observeMutations(selector, config = {}) {
    return this.page.evaluate(({ selector, config }) => {
      const target = selector ? document.querySelector(selector) : document.body;
      if (!target) throw new Error(`Target not found: ${selector || 'body'}`);
      const mutations = [];
      const observer = new MutationObserver((records) => {
        records.forEach(r => {
          mutations.push({
            type: r.type,
            target: r.target.tagName,
            addedNodes: r.addedNodes.length,
            removedNodes: r.removedNodes.length,
            attributeName: r.attributeName,
            oldValue: r.oldValue,
            timestamp: Date.now()
          });
        });
      });
      observer.observe(target, {
        childList: true,
        attributes: true,
        subtree: true,
        attributeOldValue: true,
        ...config
      });
      return { started: true, mutationCount: () => mutations.length };
    }, { selector, config });
  }

  async getComputedStyles(selector) {
    return this.page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return null;
      const styles = window.getComputedStyle(el);
      const props = {};
      for (let i = 0; i < styles.length; i++) {
        const name = styles[i];
        props[name] = styles.getPropertyValue(name);
      }
      return props;
    }, selector);
  }

  async getLocalStorage() {
    return this.page.evaluate(() => ({ ...localStorage }));
  }

  async getSessionStorage() {
    return this.page.evaluate(() => ({ ...sessionStorage }));
  }

  async getCookies() {
    return this.page.evaluate(() => {
      return document.cookie.split(';').map(c => c.trim()).filter(Boolean).map(c => {
        const [name, ...vals] = c.split('=');
        return { name: name.trim(), value: vals.join('=') };
      });
    });
  }

  async setCookie(name, value) {
    return this.page.evaluate(({ name, value }) => {
      document.cookie = `${name}=${value}; path=/;`;
    }, { name, value });
  }

  async getElementByText(text, tag = '*') {
    return this.page.evaluate(({ text, tag }) => {
      const elements = document.querySelectorAll(tag);
      for (const el of elements) {
        if (el.textContent.includes(text)) {
          return {
            tag: el.tagName,
            id: el.id,
            className: el.className,
            outerHTML: el.outerHTML.slice(0, 500)
          };
        }
      }
      return null;
    }, { text, tag });
  }

  async highlightElement(selector) {
    return this.page.evaluate((sel) => {
      const el = document.querySelector(sel);
      if (!el) return false;
      el.style.outline = '3px solid red';
      el.style.outlineOffset = '2px';
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      return true;
    }, selector);
  }

  async extractTable(selector) {
    return this.page.evaluate((sel) => {
      const table = document.querySelector(sel);
      if (!table) return null;
      const headers = Array.from(table.querySelectorAll('th')).map(th => th.textContent.trim());
      const rows = Array.from(table.querySelectorAll('tr')).slice(headers.length ? 1 : 0).map(row =>
        Array.from(row.querySelectorAll('td')).map(td => td.textContent.trim())
      );
      return { headers, rows };
    }, selector);
  }

  async extractMetaTags() {
    return this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('meta')).map(m => ({
        name: m.getAttribute('name') || m.getAttribute('property') || '',
        content: m.getAttribute('content') || '',
        httpEquiv: m.getAttribute('http-equiv') || ''
      }));
    });
  }

  async extractScriptTags() {
    return this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('script')).map(s => ({
        src: s.src,
        type: s.type,
        innerLength: s.textContent.length,
        async: s.async,
        defer: s.defer
      }));
    });
  }

  async accessShadowDOM(hostSelector) {
    return this.page.evaluate((sel) => {
      const host = document.querySelector(sel);
      if (!host || !host.shadowRoot) return null;
      const shadow = host.shadowRoot;
      return {
        mode: shadow.mode,
        innerHTML: shadow.innerHTML.slice(0, 1000),
        childCount: shadow.children.length,
        children: Array.from(shadow.querySelectorAll('*')).map(el => el.tagName)
      };
    }, hostSelector);
  }

  async accessIframeContent(iframeSelector) {
    return this.page.evaluate((sel) => {
      const iframe = document.querySelector(sel);
      if (!iframe || !iframe.contentDocument) return null;
      return {
        title: iframe.contentDocument.title,
        bodyLength: iframe.contentDocument.body?.innerHTML.length || 0,
        links: Array.from(iframe.contentDocument.querySelectorAll('a')).map(a => a.href).slice(0, 20)
      };
    }, iframeSelector);
  }

  async detectCustomElements() {
    return this.page.evaluate(() => {
      const all = document.querySelectorAll('*');
      const custom = new Set();
      all.forEach(el => {
        const tag = el.tagName.toLowerCase();
        if (tag.includes('-')) custom.add(tag);
      });
      return Array.from(custom);
    });
  }

  async findWebComponents() {
    return this.page.evaluate(() => {
      const results = [];
      const all = document.querySelectorAll('*');
      all.forEach(el => {
        const proto = Object.getPrototypeOf(el);
        if (proto.constructor.name && proto.constructor.name !== 'HTMLElement' && !proto.constructor.name.startsWith('HTML')) results.push({ tag: el.tagName, constructor: proto.constructor.name });
      });
      return results;
    });
  }

  async parseTemplateStrings(str) {
    return this.page.evaluate((s) => {
      const tpl = document.createElement('template');
      tpl.innerHTML = s;
      return { content: tpl.content.innerHTML.slice(0, 500), childCount: tpl.content.children.length };
    }, str);
  }

  async evaluateXPath(xpath) {
    return this.page.evaluate((xp) => {
      const result = document.evaluate(xp, document, null, XPathResult.ANY_TYPE, null);
      const nodes = [];
      let node = result.iterateNext();
      while (node) { nodes.push(node.tagName || node.nodeName); node = result.iterateNext(); }
      return nodes;
    }, xpath);
  }

  async detectScrollableElements() {
    return this.page.evaluate(() => {
      const all = document.querySelectorAll('*');
      const results = [];
      all.forEach(el => {
        const style = window.getComputedStyle(el);
        if (style.overflow === 'scroll' || style.overflow === 'auto' || style.overflowY === 'scroll' || style.overflowX === 'scroll') {
          results.push({ tag: el.tagName, id: el.id || '', scrollW: el.scrollWidth > el.clientWidth, scrollH: el.scrollHeight > el.clientHeight });
        }
      });
      return results.slice(0, 30);
    });
  }

  async getGridLayouts() {
    return this.page.evaluate(() => {
      const all = document.querySelectorAll('*');
      const results = [];
      all.forEach(el => {
        const style = window.getComputedStyle(el);
        if (style.display === 'grid' || style.display === 'inline-grid') results.push({ tag: el.tagName, id: el.id || '', columns: style.gridTemplateColumns, rows: style.gridTemplateRows });
      });
      return results;
    });
  }

  async getFlexLayouts() {
    return this.page.evaluate(() => {
      const all = document.querySelectorAll('*');
      const results = [];
      all.forEach(el => {
        const style = window.getComputedStyle(el);
        if (style.display === 'flex' || style.display === 'inline-flex') results.push({ tag: el.tagName, id: el.id || '', direction: style.flexDirection });
      });
      return results;
    });
  }

  async getContentEditable() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('[contenteditable]').forEach(el => {
        results.push({ tag: el.tagName, id: el.id || '', editable: el.contentEditable, text: el.textContent?.slice(0, 100) });
      });
      return results;
    });
  }

  async toggleDesignMode(state) {
    return this.page.evaluate((s) => { document.designMode = s ? 'on' : 'off'; }, state);
  }

  async detectDraggableElements() {
    return this.page.evaluate(() => {
      const results = [];
      document.querySelectorAll('[draggable="true"], [draggable=""]').forEach(el => {
        results.push({ tag: el.tagName, id: el.id || '', text: el.textContent?.slice(0, 50) });
      });
      return results;
    });
  }

  async assertSelector(selector) {
    const r = await this.querySelector(selector);
    return { exists: r !== null, details: r };
  }

  async findAllTextContaining(text) {
    return this.page.evaluate((t) => {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null, false);
      const results = [];
      let node;
      while ((node = walker.nextNode())) {
        if (node.textContent.includes(t)) results.push({ text: node.textContent.trim().slice(0, 100), parent: node.parentElement?.tagName });
      }
      return results.slice(0, 50);
    }, text);
  }

  async getAllFormsDetailed() {
    return this.page.evaluate(() => {
      return Array.from(document.querySelectorAll('form')).map(f => ({
        id: f.id,
        name: f.name,
        action: f.action,
        method: f.method,
        enctype: f.enctype,
        novalidate: f.noValidate,
        fields: Array.from(f.elements).map(e => ({
          name: e.name,
          id: e.id,
          type: e.type || e.tagName,
          value: e.value?.slice(0, 50),
          required: e.required,
          disabled: e.disabled,
          readOnly: e.readOnly,
          pattern: e.pattern,
          placeholder: e.placeholder
        }))
      }));
    });
  }

  async findOverlappingElements() {
    return this.page.evaluate(() => {
      const all = document.querySelectorAll('*');
      const results = [];
      all.forEach(el => {
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return;
        const style = window.getComputedStyle(el);
        if (style.position === 'absolute' || style.position === 'fixed') results.push({ tag: el.tagName, id: el.id || '', zIndex: style.zIndex, opacity: style.opacity, rect: { x: rect.x, y: rect.y, w: rect.width, h: rect.height } });
      });
      return results;
    });
  }

  async fullDOMMap() {
    return this.page.evaluate(() => {
      const map = { tags: {}, inputs: 0, forms: 0, links: 0, images: 0, scripts: 0, iframes: 0, storageSize: 0 };
      document.querySelectorAll('*').forEach(el => { const t = el.tagName.toLowerCase(); map.tags[t] = (map.tags[t] || 0) + 1; });
      map.inputs = document.querySelectorAll('input, textarea, select').length;
      map.forms = document.querySelectorAll('form').length;
      map.links = document.querySelectorAll('a[href]').length;
      map.images = document.querySelectorAll('img').length;
      map.scripts = document.querySelectorAll('script').length;
      map.iframes = document.querySelectorAll('iframe').length;
      try { map.storageSize = JSON.stringify(localStorage).length + JSON.stringify(sessionStorage).length; } catch {}
      return map;
    });
  }
}

module.exports = { DOMManipulation };
