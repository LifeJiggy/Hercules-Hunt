const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node graphql-finder.js <file_or_dir>'); process.exit(1); }

function load(p) {
  if (fs.statSync(p).isDirectory()) {
    return fs.readdirSync(p).filter(f => /\.(js|mjs|cjs|map)$/.test(f))
      .flatMap(f => ({ name: f, content: fs.readFileSync(path.join(p, f), 'utf-8') }));
  }
  return [{ name: path.basename(p), content: fs.readFileSync(p, 'utf-8') }];
}

const files = load(args[0]);
const endpoints = [];
const queries = [];
const mutations = [];
const subscriptions = [];
const fragments = [];
const schemaTypes = [];
const gqlLibs = [];

files.forEach(({ name, content }) => {
  // GraphQL endpoints
  const epRe = /["'`](https?:\/\/[^"'`]*\/?(?:graphql|gql|v1\/graphql|v2\/graphql|v3\/graphql|admin\/graphql|api\/graphql)[^"'`]*)["'`]/gi;
  let match;
  while ((match = epRe.exec(content)) !== null) { endpoints.push({ url: match[1], file: name }); }

  // Query operations
  const qRe = /gql`\s*(query\s+(?:[a-zA-Z_]+\s*)?[{(][\s\S]{20,1000}?`)/gis;
  while ((match = qRe.exec(content)) !== null) {
    queries.push({ operation: match[1].substring(0, 200), file: name });
  }
  const qRe2 = /["'`](query\s+\w+\s*(?:\([^)]*\))?\s*\{[\s\S]{10,1000}?["'`]\s*\))/g;
  while ((match = qRe2.exec(content)) !== null) {
    if (!match[1].includes('import')) queries.push({ operation: match[1].substring(0, 200), file: name });
  }

  // Mutation operations
  const mRe = /gql`\s*(mutation\s+(?:[a-zA-Z_]+\s*)?[{(][\s\S]{20,1000}?`)/gis;
  while ((match = mRe.exec(content)) !== null) { mutations.push({ operation: match[1].substring(0, 200), file: name }); }

  // Subscription operations
  const sRe = /gql`\s*(subscription\s+(?:[a-zA-Z_]+\s*)?[{(][\s\S]{20,1000}?`)/gis;
  while ((match = sRe.exec(content)) !== null) { subscriptions.push({ operation: match[1].substring(0, 200), file: name }); }

  // Fragments
  const fRe = /gql`\s*(fragment\s+[a-zA-Z_]+\s+on\s+[a-zA-Z_]+\s*\{[\s\S]{10,1000}?`)/gis;
  while ((match = fRe.exec(content)) !== null) { fragments.push({ operation: match[1].substring(0, 200), file: name }); }

  // Type definitions / SDL
  const sdlRe = /gql`\s*(type\s+[a-zA-Z_]+\s*\{[\s\S]{10,1000}?`)/gis;
  while ((match = sdlRe.exec(content)) !== null) { schemaTypes.push({ sdl: match[1].substring(0, 200), file: name }); }

  // GraphQL library usage
  if (/['"`](@apollo|apollo-|graphql-request|urql|relay|graphql-tag|gql\s*.{0,5})['"`]|from\s+['"`](graphql|@apollo)/.test(content)) {
    gqlLibs.push(name);
  }
  if (/['"`](gql\s*`|graphql`)/.test(content)) { gqlLibs.push(`${name} (gql literal)`); }
});

console.log(`\n${'='.repeat(70)}`);
console.log(`  GraphQL Analysis -- ${files.length} file(s)`);
console.log(`${'='.repeat(70)}`);

if (gqlLibs.length > 0) {
  const uniqueLibs = [...new Set(gqlLibs)];
  console.log(`\n  GraphQL Libraries Detected (${uniqueLibs.length} files):`);
  uniqueLibs.slice(0, 20).forEach(l => console.log(`    ${l}`));
}

console.log(`\n  Endpoints (${endpoints.length}):`);
if (endpoints.length > 0) {
  [...new Set(endpoints.map(e => e.url))].slice(0, 15).forEach(ep => console.log(`    ${ep}`));
}

console.log(`\n  Queries (${queries.length}):`);
queries.slice(0, 10).forEach(q => {
  const name = q.operation.match(/query\s+(\w+)/);
  console.log(`    [${q.file}] ${name ? name[1] : q.operation.substring(0, 60)}`);
});

console.log(`\n  Mutations (${mutations.length}):`);
mutations.slice(0, 10).forEach(m => {
  const name = m.operation.match(/mutation\s+(\w+)/);
  console.log(`    [${m.file}] ${name ? name[1] : m.operation.substring(0, 60)}`);
});

console.log(`\n  Subscriptions (${subscriptions.length}):`);
subscriptions.slice(0, 5).forEach(s => {
  console.log(`    [${s.file}] ${s.operation.substring(0, 80)}`);
});

console.log(`\n  Fragments (${fragments.length}):`);
fragments.slice(0, 5).forEach(f => {
  const name = f.operation.match(/fragment\s+(\w+)/);
  console.log(`    [${f.file}] ${name ? name[1] : f.operation.substring(0, 60)}`);
});

const names = [];
queries.concat(mutations).concat(subscriptions).concat(fragments).forEach(op => {
  const n = op.operation.match(/(?:query|mutation|subscription|fragment)\s+(\w+)/);
  if (n) names.push(n[1]);
});
if (names.length > 0) {
  console.log(`\n  Operation Names:`);
  [...new Set(names)].forEach(n => console.log(`    ${n}`));
}

console.log(`\n  Schema Types (${schemaTypes.length}):`);
schemaTypes.slice(0, 5).forEach(t => {
  const name = t.sdl.match(/type\s+(\w+)/);
  if (name) console.log(`    ${name[1]}`);
});

if (endpoints.length === 0 && queries.length === 0 && mutations.length === 0) {
  console.log(`  No GraphQL surface found.`);
}

console.log(`\n${'='.repeat(70)}\n`);
