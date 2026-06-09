#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * @typedef {Object} FormElement
 * @property {string} action - Form action URL
 * @property {string} method - HTTP method (GET/POST)
 * @property {string} id - Form ID
 * @property {string} name - Form name
 * @property {Array<{type: string, name: string, value: string, id: string, placeholder: string, required: boolean, maxlength: number}>} inputs - Input fields
 * @property {boolean} hasSubmit - Whether form has submit button
 */

/**
 * @typedef {Object} InteractiveElement
 * @property {string} tag - HTML tag
 * @property {string} type - Element type
 * @property {string} id - Element ID
 * @property {string} name - Element name
 * @property {string} value - Element value
 * @property {string} href - Link href (for anchors)
 * @property {string} selector - CSS selector
 */

/**
 * @typedef {Object} EventHandler
 * @property {string} event - Event name (onclick, onsubmit, etc.)
 * @property {string} code - Event handler code snippet
 * @property {string} selector - Element selector
 * @property {string} tag - Element tag name
 */

/**
 * @typedef {Object} UserWorkflow
 * @property {string} sourcePage - Source page URL
 * @property {string} sourceForm - Source form action/ID
 * @property {string} targetPage - Target page or submission URL
 * @property {string} method - HTTP method
 * @property {string} trigger - What triggers the transition (submit, click, redirect)
 */

/**
 * @typedef {Object} FunctionalityExtractorOptions
 * @property {string} [url] - Target URL to crawl
 * @property {string} [file] - Local file to analyze
 * @property {string} [output] - Output file path
 * @property {number} [depth=2] - Crawl depth
 * @property {boolean} [silent=false] - Suppress verbose output
 * @property {boolean} [includeHidden=false] - Include hidden input fields
 * @property {boolean} [followRedirects=true] - Follow HTTP redirects
 */

class FunctionalityExtractor {
  /**
   * @param {FunctionalityExtractorOptions} options
   */
  constructor(options = {}) {
    this.depth = options.depth || 2;
    this.silent = options.silent || false;
    this.timeout = options.timeout || 15000;
    this.includeHidden = options.includeHidden || false;
    this.followRedirects = options.followRedirects !== false;
    this.userAgent = 'Hercules-Hunt-Functionality-Extractor/1.0';
    this.forms = [];
    this.buttons = [];
    this.links = [];
    this.inputs = [];
    this.selects = [];
    this.textareas = [];
    this.eventHandlers = [];
    this.workflows = [];
    this.visited = new Set();
    this.redirectMap = new Map();
  }

  /**
   * Logs message to stderr unless silent mode is active
   * @param {string} msg
   * @param {string} [level='info']
   */
  log(msg, level = 'info') {
    if (!this.silent) {
      process.stderr.write(`[${level.toUpperCase()}] ${msg}\n`);
    }
  }

  /**
   * Fetches a URL and returns parsed response
   * @param {string} targetUrl
   * @param {number} [redirectCount=0]
   * @returns {Promise<{status: number, headers: Object, body: string, contentType: string, finalUrl: string}>}
   */
  async fetchUrl(targetUrl, redirectCount = 0) {
    const parsed = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    return new Promise((resolve, reject) => {
      const opts = {
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'GET',
        headers: {
          'User-Agent': this.userAgent,
          'Accept': 'text/html,application/xhtml+xml,application/xml,application/json,*/*',
          'Accept-Language': 'en-US,en;q=0.9',
        },
        timeout: this.timeout,
        rejectUnauthorized: false,
      };
      const req = lib.request(opts, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const status = res.statusCode;
          const headers = res.headers;
          const body = Buffer.concat(chunks).toString();
          const contentType = res.headers['content-type'] || '';
          const finalUrl = targetUrl;

          if (this.followRedirects && status >= 300 && status < 400 && headers.location && redirectCount < 5) {
            try {
              const redirectUrl = new URL(headers.location, targetUrl).href;
              this.redirectMap.set(targetUrl, redirectUrl);
              this.resolve(redirectUrl, redirectCount + 1).then(resolve).catch(reject);
              return;
            } catch {
              resolve({ status, headers, body, contentType, finalUrl });
              return;
            }
          }
          resolve({ status, headers, body, contentType, finalUrl });
        });
      });
      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout fetching ${targetUrl}`)); });
      req.on('error', (e) => reject(new Error(`Request error for ${targetUrl}: ${e.message}`)));
      req.end();
    });
  }

  /**
   * Extracts forms from HTML content
   * @param {string} content
   * @param {string} baseUrl
   * @returns {FormElement[]}
   */
  extractForms(content, baseUrl) {
    const forms = [];
    const formRegex = /<form([^>]*)>([\s\S]*?)<\/form>/gi;
    let formMatch;
    while ((formMatch = formRegex.exec(content)) !== null) {
      const formTag = formMatch[1];
      const formContent = formMatch[2];
      const actionMatch = formTag.match(/action=["']([^"']*)["']/);
      const methodMatch = formTag.match(/method=["']([^"']*)["']/);
      const idMatch = formTag.match(/id=["']([^"']*)["']/);
      const nameMatch = formTag.match(/name=["']([^"']*)["']/);
      const encTypeMatch = formTag.match(/enctype=["']([^"']*)["']/);

      let action = actionMatch ? actionMatch[1] : '';
      if (action && !action.startsWith('http')) {
        try {
          action = new URL(action, baseUrl).href;
        } catch { action = ''; }
      }

      const method = methodMatch ? methodMatch[1].toUpperCase() : 'GET';
      const id = idMatch ? idMatch[1] : '';
      const name = nameMatch ? nameMatch[1] : '';
      const enctype = encTypeMatch ? encTypeMatch[1] : 'application/x-www-form-urlencoded';

      const inputs = [];
      const inputRegex = /<input([^>]*)>/gi;
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formContent)) !== null) {
        const inputTag = inputMatch[1];
        const inputType = (inputTag.match(/type=["']([^"']*)["']/) || [])[1] || 'text';
        const inputName = (inputTag.match(/name=["']([^"']*)["']/) || [])[1] || '';
        const inputValue = (inputTag.match(/value=["']([^"']*)["']/) || [])[1] || '';
        const inputId = (inputTag.match(/id=["']([^"']*)["']/) || [])[1] || '';
        const inputPlaceholder = (inputTag.match(/placeholder=["']([^"']*)["']/) || [])[1] || '';
        const inputRequired = /required/i.test(inputTag);
        const inputMaxlength = parseInt((inputTag.match(/maxlength=["'](\d+)["']/) || [])[1], 10) || null;
        const inputAutocomplete = (inputTag.match(/autocomplete=["']([^"']*)["']/) || [])[1] || null;
        const inputDisabled = /disabled/i.test(inputTag);
        const inputReadonly = /readonly/i.test(inputTag);
        const inputPattern = (inputTag.match(/pattern=["']([^"']*)["']/) || [])[1] || null;
        const inputMin = (inputTag.match(/min=["']([^"']*)["']/) || [])[1] || null;
        const inputMax = (inputTag.match(/max=["']([^"']*)["']/) || [])[1] || null;
        const inputStep = (inputTag.match(/step=["']([^"']*)["']/) || [])[1] || null;

        if (this.includeHidden || inputType !== 'hidden') {
          inputs.push({
            type: inputType,
            name: inputName,
            value: inputValue,
            id: inputId,
            placeholder: inputPlaceholder,
            required: inputRequired,
            maxlength: inputMaxlength,
            autocomplete: inputAutocomplete,
            disabled: inputDisabled,
            readonly: inputReadonly,
            pattern: inputPattern,
            min: inputMin,
            max: inputMax,
            step: inputStep,
          });
        }
      }

      const hasSubmit = /type=["']submit["']/i.test(formContent) || /<button[^>]*type=["']submit["']/i.test(formContent);

      const formObj = {
        action,
        method,
        id,
        name,
        enctype,
        inputs,
        hasSubmit,
        rawTag: formTag.trim().slice(0, 200),
      };
      forms.push(formObj);
    }
    return forms;
  }

  /**
   * Extracts buttons from HTML content
   * @param {string} content
   * @param {string} baseUrl
   * @returns {InteractiveElement[]}
   */
  extractButtons(content, baseUrl) {
    const buttons = [];
    const patterns = [
      /<button([^>]*)>[\s\S]*?<\/button>/gi,
      /<input[^>]*type=["'](?:submit|button|reset)["'][^>]*>/gi,
    ];
    for (const pattern of patterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        const tag = match[0];
        const typeMatch = tag.match(/type=["']([^"']*)["']/);
        const idMatch = tag.match(/id=["']([^"']*)["']/);
        const nameMatch = tag.match(/name=["']([^"']*)["']/);
        const valueMatch = tag.match(/value=["']([^"']*)["']/);
        const formMatch = tag.match(/form=["']([^"']*)["']/);
        const formactionMatch = tag.match(/formaction=["']([^"']*)["']/);
        const disabled = /disabled/i.test(tag);
        const classMatch = tag.match(/class=["']([^"']*)["']/);
        const onClickMatch = tag.match(/onclick=["']([^"']*)["']/);

        let text = '';
        const textMatch = tag.match(/<button[^>]*>([\s\S]*)<\/button>/i);
        if (textMatch) {
          text = textMatch[1].replace(/<[^>]*>/g, '').trim().slice(0, 100);
        }

        let formaction = '';
        if (formactionMatch) {
          formaction = formactionMatch[1];
          if (formaction && !formaction.startsWith('http')) {
            try {
              formaction = new URL(formaction, baseUrl).href;
            } catch { formaction = ''; }
          }
        }

        buttons.push({
          tag: tag.includes('button') ? 'button' : 'input',
          type: typeMatch ? typeMatch[1] : 'submit',
          id: idMatch ? idMatch[1] : '',
          name: nameMatch ? nameMatch[1] : '',
          value: valueMatch ? valueMatch[1] : text,
          form: formMatch ? formMatch[1] : '',
          formaction,
          disabled,
          class: classMatch ? classMatch[1] : '',
          onclick: onClickMatch ? onClickMatch[1] : '',
          selector: this.buildSelector({ id: idMatch ? idMatch[1] : '', name: nameMatch ? nameMatch[1] : '', tag: 'button', type: typeMatch ? typeMatch[1] : 'submit' }),
        });
      }
    }
    return buttons;
  }

  /**
   * Extracts links from HTML content
   * @param {string} content
   * @param {string} baseUrl
   * @returns {InteractiveElement[]}
   */
  extractLinks(content, baseUrl) {
    const links = [];
    const linkRegex = /<a([^>]*)>[\s\S]*?<\/a>/gi;
    let match;
    while ((match = linkRegex.exec(content)) !== null) {
      const tag = match[1];
      const hrefMatch = tag.match(/href=["']([^"']*)["']/);
      const idMatch = tag.match(/id=["']([^"']*)["']/);
      const nameMatch = tag.match(/name=["']([^"']*)["']/);
      const classMatch = tag.match(/class=["']([^"']*)["']/);
      const relMatch = tag.match(/rel=["']([^"']*)["']/);
      const targetMatch = tag.match(/target=["']([^"']*)["']/);
      const titleMatch = tag.match(/title=["']([^"']*)["']/);
      const downloadMatch = tag.match(/download=["']([^"']*)["']/);
      const onClickMatch = tag.match(/onclick=["']([^"']*)["']/);
      const dataMatch = tag.match(/data-[\w-]+=["'][^"']*["']/g);

      let href = hrefMatch ? hrefMatch[1] : '';
      if (href && !href.startsWith('http') && !href.startsWith('#') && !href.startsWith('javascript:') && !href.startsWith('mailto:')) {
        try {
          href = new URL(href, baseUrl).href;
        } catch { href = ''; }
      }

      const textMatch = match[0].match(/<a[^>]*>([\s\S]*)<\/a>/i);
      let text = textMatch ? textMatch[1].replace(/<[^>]*>/g, '').trim() : '';

      let dataAttrs = [];
      if (dataMatch) {
        dataAttrs = dataMatch.map((d) => {
          const parts = d.split('=');
          return { key: parts[0], value: parts.slice(1).join('=').replace(/["']/g, '') };
        });
      }

      links.push({
        tag: 'a',
        type: 'link',
        id: idMatch ? idMatch[1] : '',
        name: nameMatch ? nameMatch[1] : '',
        href,
        text: text.slice(0, 200),
        class: classMatch ? classMatch[1] : '',
        rel: relMatch ? relMatch[1] : '',
        target: targetMatch ? targetMatch[1] : '',
        title: titleMatch ? titleMatch[1] : '',
        download: downloadMatch ? downloadMatch[1] : '',
        onclick: onClickMatch ? onClickMatch[1] : '',
        dataAttributes: dataAttrs,
        isInternal: href.startsWith('#'),
        isJavaScript: href.startsWith('javascript:'),
        selector: this.buildSelector({ id: idMatch ? idMatch[1] : '', tag: 'a', href: hrefMatch ? hrefMatch[1] : '' }),
      });
    }
    return links;
  }

  /**
   * Extracts all input elements outside forms
   * @param {string} content
   * @param {string} baseUrl
   * @returns {InteractiveElement[]}
   */
  extractInputs(content, baseUrl) {
    const inputs = [];
    const inputRegex = /<input([^>]*)>/gi;
    let match;
    while ((match = inputRegex.exec(content)) !== null) {
      const tag = match[1];
      if (/type=["'](?:submit|button|reset|hidden)["']/i.test(tag)) continue;
      if (/<form[\s>]/i.test(content.slice(0, match.index))) {
        const preContent = content.slice(0, match.index);
        const lastFormStart = preContent.lastIndexOf('<form');
        const lastFormEnd = preContent.lastIndexOf('</form>');
        if (lastFormStart > lastFormEnd) continue;
      }
      const type = (tag.match(/type=["']([^"']*)["']/) || [])[1] || 'text';
      const name = (tag.match(/name=["']([^"']*)["']/) || [])[1] || '';
      const value = (tag.match(/value=["']([^"']*)["']/) || [])[1] || '';
      const id = (tag.match(/id=["']([^"']*)["']/) || [])[1] || '';
      const placeholder = (tag.match(/placeholder=["']([^"']*)["']/) || [])[1] || '';
      const required = /required/i.test(tag);
      const disabled = /disabled/i.test(tag);
      const readonly = /readonly/i.test(tag);
      const autocomplete = (tag.match(/autocomplete=["']([^"']*)["']/) || [])[1] || null;
      const pattern = (tag.match(/pattern=["']([^"']*)["']/) || [])[1] || null;
      const maxlength = parseInt((tag.match(/maxlength=["'](\d+)["']/) || [])[1], 10) || null;

      inputs.push({
        tag: 'input',
        type,
        name,
        value,
        id,
        placeholder,
        required,
        disabled,
        readonly,
        autocomplete,
        pattern,
        maxlength,
        selector: this.buildSelector({ id, name, tag: 'input', type }),
      });
    }
    return inputs;
  }

  /**
   * Extracts select elements and their options
   * @param {string} content
   * @param {string} baseUrl
   * @returns {Array<{tag: string, name: string, id: string, multiple: boolean, required: boolean, disabled: boolean, options: Array<{value: string, text: string, selected: boolean}>, selector: string}>}
   */
  extractSelects(content, baseUrl) {
    const selects = [];
    const selectRegex = /<select([^>]*)>([\s\S]*?)<\/select>/gi;
    let match;
    while ((match = selectRegex.exec(content)) !== null) {
      const selectTag = match[1];
      const selectContent = match[2];
      const name = (selectTag.match(/name=["']([^"']*)["']/) || [])[1] || '';
      const id = (selectTag.match(/id=["']([^"']*)["']/) || [])[1] || '';
      const multiple = /multiple/i.test(selectTag);
      const required = /required/i.test(selectTag);
      const disabled = /disabled/i.test(selectTag);
      const size = parseInt((selectTag.match(/size=["'](\d+)["']/) || [])[1], 10) || null;

      const options = [];
      const optionRegex = /<option([^>]*)>([\s\S]*?)<\/option>/gi;
      let optMatch;
      while ((optMatch = optionRegex.exec(selectContent)) !== null) {
        const optTag = optMatch[1];
        const optText = optMatch[2].replace(/<[^>]*>/g, '').trim();
        const optValue = (optTag.match(/value=["']([^"']*)["']/) || [])[1] || optText;
        const optSelected = /selected/i.test(optTag);
        const optDisabled = /disabled/i.test(optTag);
        const optLabel = (optTag.match(/label=["']([^"']*)["']/) || [])[1] || '';
        options.push({
          value: optValue,
          text: optText.slice(0, 200),
          selected: optSelected,
          disabled: optDisabled,
          label: optLabel,
        });
      }

      const optgroupRegex = /<optgroup([^>]*)>([\s\S]*?)<\/optgroup>/gi;
      let ogMatch;
      while ((ogMatch = optgroupRegex.exec(selectContent)) !== null) {
        const ogTag = ogMatch[1];
        const ogLabel = (ogTag.match(/label=["']([^"']*)["']/) || [])[1] || '';
        const ogDisabled = /disabled/i.test(ogTag);
        const ogOptions = [];
        const ogOptRegex = /<option([^>]*)>([\s\S]*?)<\/option>/gi;
        let ogOptMatch;
        while ((ogOptMatch = ogOptRegex.exec(ogMatch[2])) !== null) {
          const oTag = ogOptMatch[1];
          const oText = ogOptMatch[2].replace(/<[^>]*>/g, '').trim();
          const oValue = (oTag.match(/value=["']([^"']*)["']/) || [])[1] || oText;
          ogOptions.push({
            value: oValue,
            text: oText.slice(0, 200),
            selected: /selected/i.test(oTag),
            disabled: /disabled/i.test(oTag),
          });
        }
        options.push(...ogOptions);
      }

      selects.push({
        tag: 'select',
        name,
        id,
        multiple,
        required,
        disabled,
        size,
        options,
        optionCount: options.length,
        selector: this.buildSelector({ id, name, tag: 'select' }),
      });
    }
    return selects;
  }

  /**
   * Extracts textarea elements
   * @param {string} content
   * @param {string} baseUrl
   * @returns {InteractiveElement[]}
   */
  extractTextareas(content, baseUrl) {
    const textareas = [];
    const textareaRegex = /<textarea([^>]*)>([\s\S]*?)<\/textarea>/gi;
    let match;
    while ((match = textareaRegex.exec(content)) !== null) {
      const tag = match[1];
      const innerText = match[2];
      const name = (tag.match(/name=["']([^"']*)["']/) || [])[1] || '';
      const id = (tag.match(/id=["']([^"']*)["']/) || [])[1] || '';
      const placeholder = (tag.match(/placeholder=["']([^"']*)["']/) || [])[1] || '';
      const rows = parseInt((tag.match(/rows=["'](\d+)["']/) || [])[1], 10) || null;
      const cols = parseInt((tag.match(/cols=["'](\d+)["']/) || [])[1], 10) || null;
      const maxlength = parseInt((tag.match(/maxlength=["'](\d+)["']/) || [])[1], 10) || null;
      const required = /required/i.test(tag);
      const disabled = /disabled/i.test(tag);
      const readonly = /readonly/i.test(tag);
      const wrap = (tag.match(/wrap=["']([^"']*)["']/) || [])[1] || null;

      textareas.push({
        tag: 'textarea',
        name,
        id,
        placeholder,
        value: innerText.trim(),
        rows,
        cols,
        maxlength,
        required,
        disabled,
        readonly,
        wrap,
        selector: this.buildSelector({ id, name, tag: 'textarea' }),
      });
    }
    return textareas;
  }

  /**
   * Extracts inline JavaScript event handlers from HTML
   * @param {string} content
   * @returns {EventHandler[]}
   */
  extractEventHandlers(content) {
    const handlers = [];
    const eventNames = [
      'onclick', 'onsubmit', 'onchange', 'onload', 'onfocus', 'onblur',
      'onmouseover', 'onmouseout', 'onmousedown', 'onmouseup',
      'onkeydown', 'onkeyup', 'onkeypress', 'oninput',
      'onscroll', 'onresize', 'onerror', 'onabort',
      'ontouchstart', 'ontouchend', 'ontouchmove',
      'ondblclick', 'oncontextmenu', 'onwheel',
      'onpointerdown', 'onpointerup', 'onpointermove',
      'onanimationend', 'onanimationstart', 'ontransitionend',
      'oncut', 'oncopy', 'onpaste',
      'onselect', 'onsearch', 'onreset',
      'oninvalid', 'onformdata',
    ];
    const tagRegex = /<(\w+)([^>]*)>/gi;
    let tagMatch;
    while ((tagMatch = tagRegex.exec(content)) !== null) {
      const tagName = tagMatch[1];
      const attrs = tagMatch[2];
      for (const event of eventNames) {
        const eventRegex = new RegExp(`${event}=["']([^"']*)["']`, 'i');
        const evtMatch = attrs.match(eventRegex);
        if (evtMatch) {
          handlers.push({
            event,
            code: evtMatch[1].trim().slice(0, 300),
            selector: `<${tagName}>`,
            tag: tagName,
          });
        }
      }
    }
    return handlers;
  }

  /**
   * Maps user workflows between pages
   * @param {string} content
   * @param {string} baseUrl
   * @returns {UserWorkflow[]}
   */
  extractWorkflows(content, baseUrl) {
    const workflows = [];

    const formRegex = /<form([^>]*)>/gi;
    let formMatch;
    while ((formMatch = formRegex.exec(content)) !== null) {
      const formTag = formMatch[1];
      const actionMatch = formTag.match(/action=["']([^"']*)["']/);
      const methodMatch = formTag.match(/method=["']([^"']*)["']/);
      const idMatch = formTag.match(/id=["']([^"']*)["']/);
      if (actionMatch && actionMatch[1]) {
        let target = actionMatch[1];
        if (!target.startsWith('http')) {
          try { target = new URL(target, baseUrl).href; } catch { target = ''; }
        }
        if (target) {
          workflows.push({
            sourcePage: baseUrl,
            sourceForm: idMatch ? idMatch[1] : '(unnamed)',
            targetPage: target,
            method: methodMatch ? methodMatch[1].toUpperCase() : 'GET',
            trigger: 'form-submit',
          });
        }
      }
    }

    const anchorRegex = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>/gi;
    let anchorMatch;
    while ((anchorMatch = anchorRegex.exec(content)) !== null) {
      let href = anchorMatch[1];
      if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;
      if (!href.startsWith('http')) {
        try { href = new URL(href, baseUrl).href; } catch { continue; }
      }
      workflows.push({
        sourcePage: baseUrl,
        sourceForm: '',
        targetPage: href,
        method: 'GET',
        trigger: 'link-click',
      });
    }

    const redirectRegex = /(?:window\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/gi;
    let redirectMatch;
    while ((redirectMatch = redirectRegex.exec(content)) !== null) {
      let target = redirectMatch[1];
      if (!target.startsWith('http')) {
        try { target = new URL(target, baseUrl).href; } catch { continue; }
      }
      workflows.push({
        sourcePage: baseUrl,
        sourceForm: '',
        targetPage: target,
        method: 'GET',
        trigger: 'js-redirect',
      });
    }

    const submitRegex = /\.submit\(\)/gi;
    while ((submitRegex = new RegExp('\\.submit\\(\\)', 'g')).exec(content) !== null) {
      const context = content.slice(Math.max(0, submitRegex.lastIndex - 100), submitRegex.lastIndex + 50);
      workflows.push({
        sourcePage: baseUrl,
        sourceForm: context.match(/id=["']([^"']*)["']/) ? context.match(/id=["']([^"']*)["']/)[1] : '(js-submit)',
        targetPage: `${baseUrl} (via JS .submit())`,
        method: 'POST',
        trigger: 'js-submit',
      });
    }

    return workflows;
  }

  /**
   * Builds a CSS selector from element attributes
   * @param {{id?: string, name?: string, tag?: string, type?: string, href?: string}} attrs
   * @returns {string}
   */
  buildSelector(attrs) {
    if (attrs.id) return `#${attrs.id}`;
    if (attrs.name && attrs.tag) return `${attrs.tag}[name="${attrs.name}"]`;
    if (attrs.type && attrs.tag) return `${attrs.tag}[type="${attrs.type}"]`;
    if (attrs.href && attrs.href !== '#') {
      const hrefVal = attrs.href.replace(/["']/g, '');
      return `a[href="${hrefVal}"]`;
    }
    return attrs.tag || 'element';
  }

  /**
   * Analyzes content from a URL or string
   * @param {string} content
   * @param {string} sourceUrl
   * @returns {void}
   */
  analyzeContent(content, sourceUrl) {
    const forms = this.extractForms(content, sourceUrl);
    const buttons = this.extractButtons(content, sourceUrl);
    const links = this.extractLinks(content, sourceUrl);
    const inputs = this.extractInputs(content, sourceUrl);
    const selects = this.extractSelects(content, sourceUrl);
    const textareas = this.extractTextareas(content, sourceUrl);
    const handlers = this.extractEventHandlers(content);
    const workflows = this.extractWorkflows(content, sourceUrl);

    this.forms.push(...forms);
    this.buttons.push(...buttons);
    this.links.push(...links);
    this.inputs.push(...inputs);
    this.selects.push(...selects);
    this.textareas.push(...textareas);
    this.eventHandlers.push(...handlers);
    this.workflows.push(...workflows);

    this.log(`Forms: ${forms.length}, Buttons: ${buttons.length}, Links: ${links.length}, Inputs: ${inputs.length}, Selects: ${selects.length}, Textareas: ${textareas.length}, EventHandlers: ${handlers.length}, Workflows: ${workflows.length}`);
  }

  /**
   * Analyzes a local file
   * @param {string} filePath
   * @returns {{file: string, forms: FormElement[], buttons: InteractiveElement[], links: InteractiveElement[], inputs: InteractiveElement[], selects: Array, textareas: InteractiveElement[], eventHandlers: EventHandler[], workflows: UserWorkflow[]}}
   */
  analyzeFile(filePath) {
    this.log(`Reading file: ${filePath}`);
    const content = fs.readFileSync(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();
    if (ext === '.html' || ext === '.htm' || ext === '.xhtml') {
      this.analyzeContent(content, filePath);
    } else if (ext === '.js' || ext === '.jsx' || ext === '.ts' || ext === '.tsx') {
      const handlers = this.extractEventHandlers(content);
      this.eventHandlers.push(...handlers);
      const workflows = this.extractWorkflows(content, filePath);
      this.workflows.push(...workflows);
      this.log(`Extracted ${handlers.length} event handlers and ${workflows.length} workflow references from JS`);
    } else {
      this.analyzeContent(content, filePath);
    }
    return {
      file: filePath,
      forms: this.forms,
      buttons: this.buttons,
      links: this.links,
      inputs: this.inputs,
      selects: this.selects,
      textareas: this.textareas,
      eventHandlers: this.eventHandlers,
      workflows: this.workflows,
    };
  }

  /**
   * Recursively crawls a URL to discover user functionalities
   * @param {string} startUrl
   * @param {number} [depth]
   * @returns {Promise<Object>}
   */
  async crawlUrl(startUrl, depth) {
    const maxDepth = depth !== undefined ? depth : this.depth;
    const queue = [{ url: startUrl, depth: 0 }];

    while (queue.length > 0) {
      const { url, depth: currentDepth } = queue.shift();
      if (this.visited.has(url) || currentDepth > maxDepth) continue;
      this.visited.add(url);

      this.log(`Crawling (depth ${currentDepth}/${maxDepth}): ${url}`);
      try {
        const response = await this.fetchUrl(url);
        const contentType = response.contentType.toLowerCase();

        if (contentType.includes('text/html') || contentType.includes('application/xhtml') || !contentType) {
          this.analyzeContent(response.body, url);

          if (currentDepth < maxDepth) {
            const linkMatches = response.body.match(/<a[^>]+href=["']([^"']+)["']/gi);
            if (linkMatches) {
              for (const link of linkMatches) {
                const hrefMatch = link.match(/href=["']([^"']+)["']/);
                if (!hrefMatch) continue;
                let href = hrefMatch[1];
                if (href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;
                try {
                  const resolved = new URL(href, url).href;
                  if (!this.visited.has(resolved) && resolved.startsWith(new URL(startUrl).origin)) {
                    queue.push({ url: resolved, depth: currentDepth + 1 });
                  }
                } catch { }
              }
            }

            const iframeMatches = response.body.match(/<iframe[^>]+src=["']([^"']+)["']/gi);
            if (iframeMatches) {
              for (const iframe of iframeMatches) {
                const srcMatch = iframe.match(/src=["']([^"']+)["']/);
                if (!srcMatch) continue;
                try {
                  const resolved = new URL(srcMatch[1], url).href;
                  if (!this.visited.has(resolved) && resolved.startsWith(new URL(startUrl).origin)) {
                    queue.push({ url: resolved, depth: currentDepth + 1 });
                  }
                } catch { }
              }
            }
          }

          const scriptMatches = response.body.match(/<script[^>]+src=["']([^"']+)["']/gi);
          if (scriptMatches) {
            for (const sm of scriptMatches) {
              const srcMatch = sm.match(/src=["']([^"']+)["']/);
              if (!srcMatch) continue;
              try {
                const jsUrl = new URL(srcMatch[1], url).href;
                if (jsUrl.endsWith('.js') && !this.visited.has(jsUrl)) {
                  this.visited.add(jsUrl);
                  try {
                    const jsResponse = await this.fetchUrl(jsUrl);
                    const jsHandlers = this.extractEventHandlers(jsResponse.body);
                    this.eventHandlers.push(...jsHandlers);
                    const jsWorkflows = this.extractWorkflows(jsResponse.body, jsUrl);
                    this.workflows.push(...jsWorkflows);
                    this.log(`Extracted ${jsHandlers.length} handlers from JS: ${jsUrl}`);
                  } catch { }
                }
              } catch { }
            }
          }
        } else if (contentType.includes('javascript')) {
          const handlers = this.extractEventHandlers(response.body);
          this.eventHandlers.push(...handlers);
          const workflows = this.extractWorkflows(response.body, url);
          this.workflows.push(...workflows);
        }
      } catch (err) {
        this.log(`Error crawling ${url}: ${err.message}`, 'warn');
      }
    }

    this.deduplicate();
    return this.generateReport({ source: startUrl, type: 'url' });
  }

  /**
   * Deduplicates collected elements by unique signature
   */
  deduplicate() {
    const formKeys = new Set();
    this.forms = this.forms.filter((f) => {
      const key = `${f.action}|${f.method}|${f.id}`;
      if (formKeys.has(key)) return false;
      formKeys.add(key);
      return true;
    });

    const buttonKeys = new Set();
    this.buttons = this.buttons.filter((b) => {
      const key = `${b.selector}|${b.value}`;
      if (buttonKeys.has(key)) return false;
      buttonKeys.add(key);
      return true;
    });

    const linkKeys = new Set();
    this.links = this.links.filter((l) => {
      const key = `${l.href}|${l.text}`;
      if (linkKeys.has(key)) return false;
      linkKeys.add(key);
      return true;
    });

    const handlerKeys = new Set();
    this.eventHandlers = this.eventHandlers.filter((h) => {
      const key = `${h.event}|${h.code.slice(0, 50)}|${h.selector}`;
      if (handlerKeys.has(key)) return false;
      handlerKeys.add(key);
      return true;
    });

    const workflowKeys = new Set();
    this.workflows = this.workflows.filter((w) => {
      const key = `${w.sourcePage}|${w.targetPage}|${w.trigger}`;
      if (workflowKeys.has(key)) return false;
      workflowKeys.add(key);
      return true;
    });
  }

  /**
   * Generates a summary report
   * @param {Object} metadata
   * @returns {Object}
   */
  generateReport(metadata = {}) {
    const formActions = [...new Set(this.forms.map((f) => f.action).filter(Boolean))];
    const formMethods = [...new Set(this.forms.map((f) => f.method))];
    const inputTypes = [...new Set(this.inputs.map((i) => i.type))];
    const eventTypes = [...new Set(this.eventHandlers.map((h) => h.event))];
    const internalLinks = this.links.filter((l) => l.isInternal);
    const externalLinks = this.links.filter((l) => !l.isInternal && !l.isJavaScript && l.href);
    const jsLinks = this.links.filter((l) => l.isJavaScript);

    const workflowSummary = {
      formSubmissions: this.workflows.filter((w) => w.trigger === 'form-submit').length,
      linkNavigations: this.workflows.filter((w) => w.trigger === 'link-click').length,
      jsRedirects: this.workflows.filter((w) => w.trigger === 'js-redirect').length,
      jsSubmits: this.workflows.filter((w) => w.trigger === 'js-submit').length,
    };

    return {
      metadata: {
        ...metadata,
        generatedAt: new Date().toISOString(),
      },
      summary: {
        totalForms: this.forms.length,
        totalButtons: this.buttons.length,
        totalLinks: this.links.length,
        totalInputs: this.inputs.length,
        totalSelects: this.selects.length,
        totalTextareas: this.textareas.length,
        totalEventHandlers: this.eventHandlers.length,
        totalWorkflows: this.workflows.length,
        formActions: formActions.length,
        formMethods,
        inputTypes,
        eventTypes,
        internalLinks: internalLinks.length,
        externalLinks: externalLinks.length,
        javaScriptLinks: jsLinks.length,
        workflowSummary,
      },
      forms: this.forms,
      buttons: this.buttons,
      links: this.links,
      inputs: this.inputs,
      selects: this.selects,
      textareas: this.textareas,
      eventHandlers: this.eventHandlers,
      workflows: this.workflows,
    };
  }

  /**
   * Runs full extraction pipeline
   * @param {FunctionalityExtractorOptions} options
   * @returns {Promise<Object>}
   */
  async run(options) {
    const startTime = Date.now();
    let report;

    if (options.file) {
      this.log(`Analyzing file: ${options.file}`);
      this.analyzeFile(options.file);
      report = this.generateReport({ source: options.file, type: 'file', input: { file: options.file } });
    } else if (options.url) {
      this.log(`Starting crawl of ${options.url} with depth ${this.depth}`);
      report = await this.crawlUrl(options.url, this.depth);
      this.log(`Crawl completed. Found ${this.forms.length} forms, ${this.buttons.length} buttons, ${this.links.length} links, ${this.inputs.length} inputs, ${this.selects.length} selects, ${this.textareas.length} textareas, ${this.eventHandlers.length} event handlers, ${this.workflows.length} workflows`);
    } else {
      throw new Error('Either --url or --file must be provided');
    }

    report.metadata.elapsed = Date.now() - startTime;

    if (options.output) {
      const outPath = path.resolve(options.output);
      fs.mkdirSync(path.dirname(outPath), { recursive: true });
      fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
      this.log(`Report written to ${outPath}`);
    }

    return report;
  }
}

/**
 * Parses command line arguments
 * @returns {FunctionalityExtractorOptions}
 */
function parseArgs() {
  const args = process.argv.slice(2);
  const options = { depth: 2, silent: false, includeHidden: false, followRedirects: true };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':
        options.url = args[++i];
        break;
      case '--file':
        options.file = args[++i];
        break;
      case '--output':
        options.output = args[++i];
        break;
      case '--depth':
        options.depth = parseInt(args[++i], 10);
        if (isNaN(options.depth) || options.depth < 1) {
          process.stderr.write('Error: --depth must be a positive integer\n');
          process.exit(1);
        }
        break;
      case '--include-hidden':
        options.includeHidden = true;
        break;
      case '--no-follow-redirects':
        options.followRedirects = false;
        break;
      case '--silent':
        options.silent = true;
        break;
      case '--timeout':
        options.timeout = parseInt(args[++i], 10);
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
      default:
        if (args[i].startsWith('-')) {
          process.stderr.write(`Unknown option: ${args[i]}\n`);
          printHelp();
          process.exit(1);
        }
        if (!options.url) options.url = args[i];
        break;
    }
  }
  if (!options.url && !options.file) {
    process.stderr.write('Error: --url or --file is required\n');
    printHelp();
    process.exit(1);
  }
  return options;
}

/**
 * Prints help text to stderr
 */
function printHelp() {
  const help = `
User Functionality Extraction Tool - extract-functionalities.js
Discovers all user-interactive elements from HTML pages and JavaScript files.

USAGE:
  node extract-functionalities.js --url <target-url> [options]
  node extract-functionalities.js --file <local-file> [options]

OPTIONS:
  --url <url>              Target URL to crawl
  --file <path>            Local HTML/JS file to analyze
  --output <path>          Write results to JSON file
  --depth <number>         Crawl depth for URL mode (default: 2)
  --include-hidden         Include hidden input fields in output
  --no-follow-redirects    Do not follow HTTP redirects
  --silent                 Suppress verbose output
  --timeout <ms>           Request timeout in milliseconds (default: 15000)
  --help, -h               Show this help message

EXAMPLES:
  node extract-functionalities.js --url https://example.com
  node extract-functionalities.js --url https://example.com --depth 3 --output functionality.json
  node extract-functionalities.js --file ./page.html --include-hidden
  node extract-functionalities.js --url https://example.com --silent > report.json
`;
  process.stderr.write(help);
}

/**
 * Main entry point
 */
async function main() {
  try {
    const options = parseArgs();
    const extractor = new FunctionalityExtractor(options);
    const report = await extractor.run(options);
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(0);
  } catch (err) {
    process.stderr.write(`FATAL ERROR: ${err.message}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { FunctionalityExtractor };
