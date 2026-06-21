const fs = require('fs');
const path = require('path');
const harden = require(path.join(__dirname, '..', 'utils', 'harden-base.js'));

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node dom-clobbering-detector.js <file.js>'); process.exit(1); }

const loaded = harden.safeLoadFile(args[0]);
if (!loaded.ok) { console.error(`Error: ${loaded.error}`); process.exit(1); }
const code = loaded.content;

const CLUBBERING_PATTERNS = [
  { type: 'form_clobbering', re: /<form\s[^>]*name\s*=\s*["'](\w+)["']/gi, risk: 'window.formName accessed as global' },
  { type: 'anchor_clobbering', re: /<a\s[^>]*name\s*=\s*["'](\w+)["']/gi, risk: 'window.anchorName overrides global' },
  { type: 'img_clobbering', re: /<img[^>]*name\s*=\s*["'](\w+)["']/gi, risk: 'window.imgName conflicts' },
  { type: 'embed_clobbering', re: /<embed[^>]*name\s*=\s*["'](\w+)["']/gi, risk: 'Plugin name shadowing' },
  { type: 'object_clobbering', re: /<object[^>]*name\s*=\s*["'](\w+)["']/gi, risk: 'Object element name shadowing' },
];

const CLUBBERED_GLOBALS = [
  'children', 'all', 'forms', 'images', 'links', 'scripts', 'title', 'body', 'head',
  'cookie', 'location', 'name', 'status', 'length', 'closed', 'frames', 'self', 'parent',
  'top', 'opener', 'document', 'history', 'navigator', 'screen', 'localStorage',
  'sessionStorage', 'console', 'fetch', 'XMLHttpRequest', 'WebSocket', 'atob', 'btoa',
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
];

function findFormChildClobbering(content) {
  const results = [];
  const formRe = /<form[^>]*>([\s\S]*?)<\/form>/gi;
  let formMatch;
  while ((formMatch = formRe.exec(content)) !== null) {
    const formContent = formMatch[0];
    const nameRe = /<(?:input|select|textarea|button)[^>]*name\s*=\s*["'](\w+)["']/gi;
    let m;
    while ((m = nameRe.exec(formContent)) !== null) {
      const name = m[1];
      if (CLUBBERED_GLOBALS.includes(name.toLowerCase())) {
        results.push({ type: 'form_global_shadow', element: m[0].substring(0, 80), name, global: name, risk: `Form child name "${name}" shadows window.${name}` });
      }
    }
  }
  return results;
}

function findIDClobbering(content) {
  const results = [];
  const idRe = /id\s*=\s*["'](\w+)["']/gi;
  let m;
  while ((m = idRe.exec(content)) !== null) {
    const id = m[1];
    if (CLUBBERED_GLOBALS.includes(id.toLowerCase())) {
      const ctx = content.substring(Math.max(0, m.index - 40), Math.min(content.length, m.index + 60));
      results.push({ type: 'id_global_shadow', element: ctx.substring(0, 100), name: id, global: id, risk: `Element ID "${id}" shadows window.${id}` });
    }
  }
  return results;
}

function findClobberingAccess(content) {
  const results = [];
  for (const global of CLUBBERED_GLOBALS.slice(0, 10)) {
    const accessRe = new RegExp(`\\b${global}\\b(?!\\s*[:=])`, 'g');
    let m;
    while ((m = accessRe.exec(content)) !== null) {
      const before = content.substring(Math.max(0, m.index - 30), m.index);
      if (/window\.|self\.|this\.|globalThis\./.test(before)) continue;
      const after = content.substring(m.index + m[0].length, Math.min(content.length, m.index + 20));
      if (/^\s*[.([]/.test(after)) continue;
      results.push({ type: 'bare_global_access', global, line: content.substring(0, m.index).split('\n').length });
      break;
    }
  }
  return results;
}

const htmlTags = findDOMStrings(code);
const formClobbers = findFormChildClobbering(code);
const idClobbers = findIDClobbering(code);
const accessPatterns = findClobberingAccess(code);

function findDOMStrings(content) {
  const results = [];
  const htmlRe = /(?:\/\/\s*|["'`])\s*(<[a-z]+[^>]*>[\s\S]{0,500}<\/[a-z]+>)\s*["'`]/gi;
  let m;
  while ((m = htmlRe.exec(content)) !== null) results.push(m[1].substring(0, 150));
  return results;
}

console.log(`\n========================================`);
console.log(`  DOM Clobbering Detection`);
console.log(`========================================`);
console.log(`  HTML string literals:   ${htmlTags.length}`);
console.log(`  Form child clobbers:    ${formClobbers.length}`);
console.log(`  ID global shadows:      ${idClobbers.length}`);
console.log(`  Bare global reads:      ${accessPatterns.length}`);

if (formClobbers.length > 0) {
  console.log(`\n  Form child → global shadow:`);
  formClobbers.slice(0, 10).forEach(f => console.log(`    [!] "${f.name}" shadows window.${f.global} — ${f.element.substring(0, 60)}`));
}
if (idClobbers.length > 0) {
  console.log(`\n  Element ID → global shadow:`);
  idClobbers.slice(0, 10).forEach(f => console.log(`    [!] "${f.name}" shadows window.${f.global} — ${f.element.substring(0, 60)}`));
}
if (accessPatterns.length > 0) {
  console.log(`\n  Bare global access (may be clobbered):`);
  accessPatterns.slice(0, 10).forEach(f => console.log(`    Line ${f.line}: bare "${f.global}" reference`));
}
console.log('');
