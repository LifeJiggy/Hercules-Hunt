const { JSDOM } = require('jsdom');

function createBrowserMock(url = 'https://target.com') {
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    url,
    pretendToBeVisual: true,
    runScripts: 'outside-only',
    resources: 'usable',
  });

  const { window } = dom;
  const { document } = window;

  const mockFetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url;
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'text/html']]),
      json: async () => ({}),
      text: async () => '',
      url,
    };
  };

  window.fetch = mockFetch;
  window.localStorage = {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; },
    clear() { this._data = {}; },
    get length() { return Object.keys(this._data).length; },
    key(i) { return Object.keys(this._data)[i] || null; },
  };
  window.sessionStorage = {
    _data: {},
    getItem(k) { return this._data[k] || null; },
    setItem(k, v) { this._data[k] = String(v); },
    removeItem(k) { delete this._data[k]; },
    clear() { this._data = {}; },
    get length() { return Object.keys(this._data).length; },
    key(i) { return Object.keys(this._data)[i] || null; },
  };

  window.caches = {
    open: async () => ({
      match: async () => null,
      put: async () => {},
      keys: async () => [],
      delete: async () => true,
    }),
    keys: async () => [],
    has: async () => false,
    delete: async () => true,
  };

  window.navigator = {
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    sendBeacon: () => true,
    serviceWorker: { controller: null, register: async () => ({}) },
    storage: { getDirectory: async () => ({}) },
    credentials: { get: async () => null },
  };

  window.indexedDB = {
    open: () => ({
      onupgradeneeded: null,
      onsuccess: null,
      onerror: null,
      result: {},
      error: null,
    }),
    deleteDatabase: () => ({}),
  };

  window.openDatabase = () => ({});

  window.postMessage = (msg, targetOrigin) => {
    window.dispatchEvent(new window.MessageEvent('message', {
      data: msg,
      origin: targetOrigin || '*',
      source: window,
    }));
  };

  window.getComputedStyle = (el) => ({
    getPropertyValue: () => '',
    position: 'static',
    zIndex: 'auto',
  });

  window.getEventListeners = () => [];

  window.MutationObserver = class {
    constructor(cb) { this.cb = cb; this.observe = () => {}; this.disconnect = () => {}; }
    observe() {}
    disconnect() {}
  };

  window.trustedTypes = { createPolicy: () => ({ createHTML: (s) => s, createScriptURL: (s) => s }) };

  return { window, document, dom };
}

function createMockPage(options = {}) {
  const cookies = options.cookies || [];
  const localStorageData = options.localStorage || {};
  const sessionStorageData = options.sessionStorage || {};
  const pageUrl = options.url || 'https://target.com/page';
  return {
    url: () => pageUrl,
    goto: async () => {},
    close: async () => {},
    evaluate: async (fn, ...args) => {
      if (typeof fn === 'function') {
        try { return fn(...args); } catch { return {}; }
      }
      return {};
    },
    $: async () => null,
    $$: async () => [],
    context: () => ({
      cookies: async () => cookies,
      browser: () => ({
        newContext: async () => ({
          goto: async () => {},
          close: async () => {}
        })
      })
    }),
    fill: async () => {},
    click: async () => {},
    waitForNavigation: async () => {},
    screenshot: async () => Buffer.from(''),
  };
}

module.exports = { createBrowserMock, createMockPage };
