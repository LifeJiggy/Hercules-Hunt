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
}

module.exports = { DOMManipulation };
