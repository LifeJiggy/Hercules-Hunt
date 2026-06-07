class PrototypePollution {
  constructor(page) {
    this.page = page;
    this.findings = [];
  }

  async detectPollutionVulnerability() {
    return this.page.evaluate(() => {
      const results = {};
      const testKey = '__proto__test_' + Date.now();
      const testObj = {};
      try {
        Object.prototype[testKey] = true;
        results.vulnerable = ({})[testKey] === true;
        delete Object.prototype[testKey];
      } catch { results.vulnerable = false; }
      results.gadgets = [];
      if (typeof Object.prototype.then !== 'undefined') results.gadgets.push('Object.prototype.then');
      if (typeof Array.prototype.flat !== 'undefined') results.gadgets.push('Array.prototype.flat');
      if (typeof String.prototype.trim !== 'undefined') results.gadgets.push('String.prototype.trim');
      return results;
    });
  }

  async detectLibraryPollution() {
    return this.page.evaluate(() => {
      const results = {};
      if (typeof $ !== 'undefined') {
        try {
          $.extend(true, {}, JSON.parse('{"__proto__": {"polluted": true}}'));
          results.jQuery = ({})['polluted'] === true;
        } catch { results.jQuery = false; }
      }
      if (typeof _ !== 'undefined') {
        try {
          _.merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));
          results.lodash = ({})['polluted'] === true;
        } catch {
          try {
            _.defaultsDeep({}, JSON.parse('{"__proto__": {"polluted": true}}'));
            results.lodash = ({})['polluted'] === true;
          } catch { results.lodash = false; }
        }
      }
      if (typeof angular !== 'undefined') {
        try {
          const merged = angular.merge({}, JSON.parse('{"__proto__": {"polluted": true}}'));
          results.angular = ({})['polluted'] === true;
        } catch { results.angular = false; }
      }
      if (typeof Object.assign !== 'undefined') {
        try {
          const target = {};
          Object.assign(target, JSON.parse('{"__proto__": {"polluted": true}}'));
          results.objectAssign = target['polluted'] || ({})['polluted'] || false;
        } catch { results.objectAssign = false; }
      }
      return results;
    });
  }

  async detectDOMClobbering() {
    return this.page.evaluate(() => {
      const results = {};
      const anchors = document.querySelectorAll('a[id], a[name]');
      anchors.forEach(a => {
        const id = a.id || a.name;
        if (id && typeof window[id] !== 'undefined') {
          results[id] = { type: 'anchor', href: a.href };
        }
      });
      const forms = document.querySelectorAll('form[id], form[name]');
      forms.forEach(f => {
        const id = f.id || f.name;
        if (id && typeof window[id] !== 'undefined') {
          results[id] = { type: 'form', action: f.action };
        }
      });
      const embeds = document.querySelectorAll('embed[id], object[id], iframe[id]');
      embeds.forEach(e => {
        const id = e.id;
        if (id && typeof window[id] !== 'undefined') {
          results[id] = { type: e.tagName.toLowerCase(), src: e.src || e.data };
        }
      });
      return results;
    });
  }

  async testScriptGadgets() {
    return this.page.evaluate(() => {
      const results = [];
      const scripts = document.querySelectorAll('script[src]');
      const gadgets = {
        'innerHTML': /\.innerHTML\s*=.*(?:__proto__|constructor|prototype)/,
        'document.write': /document\.write\(.*(?:__proto__|constructor|prototype)/,
        'eval': /eval\(.*(?:__proto__|constructor|prototype)/,
        'location': /location\s*=.*(?:__proto__|constructor|prototype)/
      };
      scripts.forEach(s => {
        const code = s.textContent;
        if (!code) return;
        for (const [name, pattern] of Object.entries(gadgets)) {
          if (pattern.test(code)) {
            results.push({ sink: name, script: s.src || 'inline' });
          }
        }
      });
      return results;
    });
  }

  async testMergeFunctions() {
    return this.page.evaluate(() => {
      const mergePatterns = [
        { name: 'String.prototype.replace', fn: String.prototype.replace },
        { name: 'Array.prototype.concat', fn: Array.prototype.concat },
        { name: 'Array.prototype.map', fn: Array.prototype.map },
        { name: 'Array.prototype.filter', fn: Array.prototype.filter },
        { name: 'Array.prototype.reduce', fn: Array.prototype.reduce },
        { name: 'Array.prototype.push', fn: Array.prototype.push },
        { name: 'Object.assign-like spread', fn: null }
      ];
      return mergePatterns.map(m => m.name);
    });
  }

  async pollutionToXSS(pollutedProperty, payload) {
    return this.page.evaluate(({ prop, payload }) => {
      const scripts = document.querySelectorAll('script');
      const results = [];
      scripts.forEach(s => {
        const code = s.textContent;
        if (code && (code.includes('innerHTML') || code.includes('outerHTML'))) {
          if (code.includes(prop)) results.push({ script: s.src || 'inline', code: code.slice(0, 200) });
        }
      });
      return results;
    }, { prop: pollutedProperty, payload });
  }

  async testAllVectors() {
    console.log('[PrototypePollution] Running all pollution tests...');
    const results = {
      basicPollution: await this.detectPollutionVulnerability(),
      libraryPollution: await this.detectLibraryPollution(),
      domClobbering: await this.detectDOMClobbering(),
      scriptGadgets: await this.testScriptGadgets()
    };
    if (results.basicPollution.vulnerable) {
      this.findings.push({ type: 'prototype-pollution', vector: 'Object.prototype', severity: 'CRITICAL' });
    }
    for (const [lib, vulnerable] of Object.entries(results.libraryPollution)) {
      if (vulnerable) this.findings.push({ type: 'library-pollution', library: lib, severity: 'CRITICAL' });
    }
    const clobberCount = Object.keys(results.domClobbering).length;
    if (clobberCount > 0) this.findings.push({ type: 'dom-clobbering', count: clobberCount, severity: 'HIGH' });
    if (results.scriptGadgets.length) this.findings.push({ type: 'pollution-gadgets', count: results.scriptGadgets.length, severity: 'HIGH' });
    return results;
  }

  async testJSONParsePollution() {
    return this.page.evaluate(() => {
      const results = {};
      try {
        const o = JSON.parse('{"__proto__": {"polluted": true}}');
        results.viaJSONParse = ({})['polluted'] === true;
      } catch { results.viaJSONParse = false; }
      try {
        const o = JSON.parse('{"constructor": {"prototype": {"polluted": true}}}');
        results.viaConstructor = ({})['polluted'] === true;
      } catch { results.viaConstructor = false; }
      return results;
    });
  }

  async testURLParamsPollution() {
    return this.page.evaluate(() => {
      const up = new URLSearchParams('__proto__[polluted]=true');
      const obj = {};
      for (const [k, v] of up) { obj[k] = v; }
      return { vulnerable: ({})['polluted'] === true };
    });
  }

  async testFormDataPollution() {
    return this.page.evaluate(() => {
      const fd = new FormData();
      fd.append('__proto__[polluted]', 'true');
      const obj = {};
      fd.forEach((v, k) => { obj[k] = v; });
      return { vulnerable: ({})['polluted'] === true };
    });
  }

  async testObjectAssign() {
    return this.page.evaluate(() => {
      try {
        const t = {}; Object.assign(t, JSON.parse('{"__proto__": {"polluted": true}}'));
        return { viaObjectAssign: ({})['polluted'] === true };
      } catch { return { viaObjectAssign: false }; }
    });
  }

  async testSpreadOperator() {
    return this.page.evaluate(() => {
      try {
        const malicious = JSON.parse('{"__proto__": {"polluted": true}}');
        const result = { ...malicious };
        return { viaSpread: ({})['polluted'] === true };
      } catch { return { viaSpread: false }; }
    });
  }

  async testReducePollution() {
    return this.page.evaluate(() => {
      try {
        [{ a: 1 }, { '__proto__': { 'polluted': true } }].reduce((a, b) => ({ ...a, ...b }), {});
        return { viaReduce: ({})['polluted'] === true };
      } catch { return { viaReduce: false }; }
    });
  }

  async testHasOwnPropertyBypass() {
    return this.page.evaluate(() => {
      const o = {};
      if (o.hasOwnProperty('polluted')) return { bypassed: false };
      try {
        Object.prototype.polluted = true;
        return { bypassed: !o.hasOwnProperty('polluted'), viaHasOwn: o.hasOwnProperty('polluted') };
      } finally { delete Object.prototype.polluted; }
    });
  }

  async testForInGadget() {
    return this.page.evaluate(() => {
      const gadgets = [];
      for (const key in {}) {
        if (Object.prototype.hasOwnProperty.call({}, key)) continue;
        gadgets.push(key);
      }
      return { extraGadgets: gadgets };
    });
  }

  async testElectronContextBridge() {
    return this.page.evaluate(() => {
      if (typeof window.require === 'function' || typeof process !== 'undefined') return { isElectron: true, contextBridgeAvailable: typeof window.electronAPI !== 'undefined' };
      return { isElectron: false };
    });
  }

  async testPolyfillLibraries() {
    return this.page.evaluate(() => {
      const libs = {};
      if (typeof $ !== 'undefined') { try { libs.jQuery = $.fn && $.fn.jquery; } catch {} }
      if (typeof _ !== 'undefined') { try { libs.lodash = _.VERSION || true; } catch {} }
      if (typeof angular !== 'undefined') { try { libs.angular = angular.version?.full || true; } catch {} }
      if (typeof React !== 'undefined') { try { libs.react = React.version; } catch {} }
      if (typeof Ext !== 'undefined') libs.sencha = true;
      if (typeof MooTools !== 'undefined') libs.mootools = true;
      if (typeof Prototype !== 'undefined') libs.prototypejs = true;
      if (typeof dojo !== 'undefined') libs.dojo = true;
      return libs;
    });
  }

  async testCloneDeep(obj) {
    return this.page.evaluate(() => {
      try {
        const cloned = JSON.parse(JSON.stringify({ '__proto__': { 'polluted': true } }));
        return { viaCloneDeep: ({})['polluted'] === true };
      } catch { return { viaCloneDeep: false }; }
    });
  }

  async fullPollutionChain() {
    console.log('[PrototypePollution] Full chain analysis...');
    const r = await this.testAllVectors();
    const additional = {
      jsonParse: await this.testJSONParsePollution(),
      urlParams: await this.testURLParamsPollution(),
      formData: await this.testFormDataPollution(),
      objectAssign: await this.testObjectAssign(),
      spread: await this.testSpreadOperator(),
      reduce: await this.testReducePollution(),
      hasOwnBypass: await this.testHasOwnPropertyBypass(),
      forInGadgets: await this.testForInGadget(),
      polyfills: await this.testPolyfillLibraries()
    };
    return { ...r, additional };
  }
}

module.exports = { PrototypePollution };
