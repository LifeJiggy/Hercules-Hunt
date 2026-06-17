const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node deep-analyzer.js <file_or_dir>'); process.exit(1); }

const inputPath = args[0];
const jsonOutput = args.includes('--json');
const jsonFlagIdx = args.indexOf('--json');
const outputJsonPath = jsonFlagIdx > -1 && args[jsonFlagIdx + 1] ? args[jsonFlagIdx + 1] : null;

function loadFiles(p) {
  if (fs.statSync(p).isDirectory()) {
    return fs.readdirSync(p).filter(f => f.endsWith('.js') || f.endsWith('.mjs') || f.endsWith('.cjs'))
      .map(f => ({ name: f, content: fs.readFileSync(path.join(p, f), 'utf-8') }));
  }
  return [{ name: path.basename(p), content: fs.readFileSync(p, 'utf-8') }];
}

const files = loadFiles(inputPath);
const allContent = files.map(f => f.content).join('\n');
const allFindings = {};

function findings(category, items) {
  if (!allFindings[category]) allFindings[category] = [];
  allFindings[category].push(...items);
}

function unique(arr) { return [...new Set(arr)]; }

function printSection(title, items, maxShow = 20) {
  console.log(`\n${'='.repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${'='.repeat(60)}`);
  if (items.length === 0) { console.log('  (none found)'); return; }
  items.slice(0, maxShow).forEach(i => console.log(`  ${i.substring(0, 150)}`));
  if (items.length > maxShow) console.log(`  ... and ${items.length - maxShow} more`);
}

files.forEach(({ name, content }) => {

  // ── Feature 1: JWT Decoder ──
  const jwtRegex = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  let match;
  while ((match = jwtRegex.exec(content)) !== null) {
    try {
      const parts = match[0].split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
      const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
      findings('1_JWT_Tokens', [
        `[${name}] ${match[0].substring(0, 60)}...`,
        `  Header: ${JSON.stringify(header)}`,
        `  Payload: ${JSON.stringify(payload)}`,
        `  Claims: ${Object.keys(payload).join(', ')}`,
      ]);
    } catch (e) {}
  }

  // ── Feature 2: Cloud Service Enumeration ──
  const s3Patterns = [
    { type: 'S3 Bucket', re: /["']([a-z0-9.-]+\.s3\.amazonaws\.com)["']/gi },
    { type: 'S3 Bucket', re: /["']([a-z0-9.-]+\.s3-website[^"']+)["']/gi },
    { type: 'S3 Bucket', re: /s3:\/\/([a-z0-9.-]+)/gi },
    { type: 'S3 Bucket', re: /["'](https?:\/\/[a-z0-9.-]+\.s3\.[^"']+)["']/gi },
  ];
  for (const p of s3Patterns) {
    while ((match = p.re.exec(content)) !== null) {
      findings('2_Cloud_Services', [`[S3] ${match[1]} in ${name}`]);
    }
  }

  const firebaseRe = /[a-z0-9-]+\.(firebaseio\.com|firebasedatabase\.app|firebaseapp\.com|web\.app)/gi;
  while ((match = firebaseRe.exec(content)) !== null) {
    findings('2_Cloud_Services', [`[Firebase] ${match[0]} in ${name}`]);
  }

  const gcpRe = /[a-z0-9-]+\.(cloudfunctions\.net|appspot\.com|uc\.r\.appspot\.com)/gi;
  while ((match = gcpRe.exec(content)) !== null) {
    findings('2_Cloud_Services', [`[GCP] ${match[0]} in ${name}`]);
  }

  const azureRe = /[a-z0-9-]+\.(blob\.core\.windows\.net|azurewebsites\.net|azureedge\.net|azurefd\.net)/gi;
  while ((match = azureRe.exec(content)) !== null) {
    findings('2_Cloud_Services', [`[Azure] ${match[0]} in ${name}`]);
  }

  const cloudfrontRe = /[a-z0-9]+\.cloudfront\.net/gi;
  while ((match = cloudfrontRe.exec(content)) !== null) {
    findings('2_Cloud_Services', [`[CloudFront] ${match[0]} in ${name}`]);
  }

  const lambdaRe = /[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws/gi;
  while ((match = lambdaRe.exec(content)) !== null) {
    findings('2_Cloud_Services', [`[Lambda] ${match[0]} in ${name}`]);
  }

  // ── Feature 3: GraphQL Schema Extraction ──
  const gqlPatterns = [
    { type: 'Query', re: /query\s+(?:[a-zA-Z_]+\s*)?[{\(][\s\S]{10,}?}/g },
    { type: 'Mutation', re: /mutation\s+(?:[a-zA-Z_]+\s*)?[{\(][\s\S]{10,}?}/g },
    { type: 'Subscription', re: /subscription\s+(?:[a-zA-Z_]+\s*)?[{\(][\s\S]{10,}?}/g },
    { type: 'Fragment', re: /fragment\s+[a-zA-Z_]+\s+on\s+[a-zA-Z_]+\s*\{[\s\S]{5,}?\}/g },
  ];
  for (const p of gqlPatterns) {
    while ((match = p.re.exec(content)) !== null) {
      const short = match[0].trim().substring(0, 120).replace(/\s+/g, ' ');
      findings('3_GraphQL_Operations', [`[${p.type}] ${short} in ${name}`]);
    }
  }

  const gqlEndpointRe = /["'](https?:\/\/[^"']*\/?(?:graphql|gql|v1\/graphql|v2\/graphql)[^"']*)["']/gi;
  while ((match = gqlEndpointRe.exec(content)) !== null) {
    findings('3_GraphQL_Endpoints', [`${match[1]} in ${name}`]);
  }

  // ── Feature 4: Source Map Auto-Discovery ──
  const smRe = /sourceMappingURL=([^\s"'\)]+)/g;
  while ((match = smRe.exec(content)) !== null) {
    findings('4_Source_Maps', [`${match[1]} in ${name}`]);
  }

  // ── Feature 5: API Route Tree ──
  const routeRe = /["'`](\/[a-zA-Z0-9_\-{}]+(?:\/[a-zA-Z0-9_\-{}]+){1,10})["'`]/g;
  const routes = [];
  while ((match = routeRe.exec(content)) !== null) {
    const r = match[1];
    if (r.length > 2 && r.length < 150 && !r.includes(' ')) routes.push(r);
  }
  const routeGroups = {};
  unique(routes).forEach(r => {
    const prefix = r.split('/').slice(0, 3).join('/');
    if (!routeGroups[prefix]) routeGroups[prefix] = [];
    routeGroups[prefix].push(r);
  });
  const routeCount = Object.keys(routeGroups).length;
  if (routeCount > 0) {
    const prefixes = Object.keys(routeGroups).sort();
    findings('5_Route_Tree', [`${routeCount} route groups in ${name}`]);
    prefixes.slice(0, 15).forEach(p => {
      findings('5_Route_Tree', [`  ${p} (${routeGroups[p].length} routes)`]);
    });
  }

  // ── Feature 6: Entropy Scanner ──
  const entropyRe = /["'`]([A-Za-z0-9_\-]{32,64})["'`]/g;
  while ((match = entropyRe.exec(content)) !== null) {
    const s = match[1];
    const charFreq = {};
    for (const c of s) charFreq[c] = (charFreq[c] || 0) + 1;
    let entropy = 0;
    const len = s.length;
    for (const c in charFreq) {
      const p = charFreq[c] / len;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    if (entropy > 4.5 && !/^[A-Z0-9]+$/.test(s) && !/^[a-z0-9]+$/.test(s)) {
      findings('6_High_Entropy', [`[entropy=${entropy.toFixed(2)}] ${s.substring(0, 50)} in ${name}`]);
    }
  }

  // ── Feature 7: OAuth Flow Analysis ──
  const oauthPatterns = [
    { type: 'OAuth Client ID', re: /["'`](client_id|clientId)["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]/gi },
    { type: 'OAuth Redirect URI', re: /["'`](redirect_uri|redirectUri)["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]/gi },
    { type: 'OAuth Scope', re: /["'`](scope|scopes)["'`]\s*[:=]\s*["'`]([^"'`]{10,})["'`]/gi },
    { type: 'OAuth Audience', re: /["'`]audience["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]/gi },
    { type: 'OAuth Domain', re: /["'`]domain["'`]\s*[:=]\s*["'`]([^"'`]+\.auth0\.com|[^"'`]+\.okta\.com|[^"'`]+\.onelogin\.com)["'`]/gi },
  ];
  for (const p of oauthPatterns) {
    while ((match = p.re.exec(content)) !== null) {
      const val = match[2] || match[1];
      findings('7_OAuth_Config', [`[${p.type}] ${val.substring(0, 100)} in ${name}`]);
    }
  }

  const googleClientRe = /[0-9]+-[a-zA-Z0-9]+\.apps\.googleusercontent\.com/g;
  while ((match = googleClientRe.exec(content)) !== null) {
    findings('7_OAuth_Config', [`[Google OAuth Client] ${match[0]} in ${name}`]);
  }

  // ── Feature 8: Hardcoded IP & Port Finder ──
  const ipPortRe = /["'`](https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})(?::(\d+))?[^"'`]*)["'`]/g;
  while ((match = ipPortRe.exec(content)) !== null) {
    findings('8_Internal_IPs', [`${match[1]} in ${name}`]);
  }

  // ── Feature 9: Email Template Extraction (potential SSTI) ──
  const emailTemplateRe = /["'`]([^"'`]{20,}?\{\{[^}]+\}[^"'`]{20,}?)["'`]/g;
  while ((match = emailTemplateRe.exec(content)) !== null) {
    findings('9_Email_Templates', [`${match[1].substring(0, 120)} in ${name}`]);
  }

  const sstiPatterns = [
    { type: 'Jinja2', re: /\{\{[^}]{5,}\}\}/g },
    { type: 'ERB', re: /<%=?[^%]{5,}%>/g },
    { type: 'Handlebars', re: /\{\{[{#/][^}]{5,}\}\}/g },
    { type: 'Template Literal', re: /`[^`]*\$\{[^}]{5,\}[^`]*`/g },
  ];
  for (const p of sstiPatterns) {
    while ((match = p.re.exec(content)) !== null) {
      findings('9_SSTI_Probes', [`[${p.type}] ${match[0].substring(0, 80)} in ${name}`]);
    }
  }

  // ── Feature 10: Feature Flag Reporter ──
  const flagNames = ['featureFlag', 'feature_flag', 'featureFlags', 'activeFeatures', 'active_features',
    'enabledFeatures', 'available_features', 'availableFeatures', 'flags', '__FLAGS', '__FEATURES'];
  const flagRegex = new RegExp(`["'\`](${flagNames.join('|')})["'\`]\\s*[:=]\\s*\\{`, 'gi');
  while ((match = flagRegex.exec(content)) !== null) {
    const start = content.indexOf(match[0]);
    const block = content.substring(start, start + 500);
    const disabledFlags = block.match(/"([a-zA-Z]+)"\s*:\s*false/g);
    const enabledFlags = block.match(/"([a-zA-Z]+)"\s*:\s*true/g);
    if (disabledFlags) disabledFlags.forEach(f => findings('10_Feature_Flags', [`[DISABLED] ${f} in ${name}`]));
    if (enabledFlags) enabledFlags.forEach(f => findings('10_Feature_Flags', [`[ENABLED]  ${f} in ${name}`]));
  }

  // ── Feature 11: Third-Party Service Mapper ──
  const thirdParty = [
    { service: 'Stripe', re: /pk_(live|test)_[A-Za-z0-9]{24,}|sk_(live|test)_[A-Za-z0-9]{24,}|["']stripe["']/gi },
    { service: 'Auth0', re: /["'](?:auth0|Auth0)["']|[a-zA-Z0-9-]+\.auth0\.com/gi },
    { service: 'Firebase', re: /["'](?:firebase|Firebase)["']|[a-z0-9-]+\.firebaseio\.com/gi },
    { service: 'Algolia', re: /algolia|Algolia|["']applicationId["'].*["'][A-Z0-9]+["']/gi },
    { service: 'SendGrid', re: /sendgrid|SendGrid|SG\.[A-Za-z0-9_-]+/gi },
    { service: 'Twilio', re: /twilio|Twilio|AC[A-Z0-9a-z]{32}/gi },
    { service: 'Mapbox', re: /mapbox|Mapbox|pk\.eyJ[A-Za-z0-9_-]+/gi },
    { service: 'Cloudinary', re: /cloudinary|Cloudinary|["']cloudName["']/gi },
    { service: 'Sentry', re: /sentry|Sentry|["']dsn["']/gi },
    { service: 'Datadog', re: /datadog|Datadog|["']applicationId["']/gi },
    { service: 'New Relic', re: /newrelic|NewRelic|["']licenseKey["'"]/gi },
    { service: 'OpenAI', re: /openai|OpenAI|sk-[A-Za-z0-9]{20,}/gi },
    { service: 'Anthropic', re: /anthropic|Anthropic|sk-ant-/gi },
    { service: 'Google Maps', re: /AIza[0-9A-Za-z\-_]{35}/gi },
    { service: 'Segment', re: /segment|Segment|["']writeKey["']/gi },
    { service: 'Amplitude', re: /amplitude|Amplitude|["']apiKey["'].*["'][a-z0-9]+["']/gi },
    { service: 'Intercom', re: /intercom|Intercom|["']app_id["']/gi },
    { service: 'Fullstory', re: /fullstory|FullStory|["']orgId["']/gi },
    { service: 'Hotjar', re: /hotjar|HotJar|["']hjid["']|["']hjsv["']/gi },
    { service: 'Okta', re: /okta|Okta|["']okta["']/gi },
  ];
  for (const tp of thirdParty) {
    while ((match = tp.re.exec(content)) !== null) {
      findings('11_Third_Party_Services', [`${tp.service} in ${name}`]);
    }
  }

  // ── Feature 12: Webhook URL Collector ──
  const webhookRe = /["'`](https?:\/\/[^"'`]*(?:webhook|callback|hook|notify|event)[^"'`]*)["'`]/gi;
  while ((match = webhookRe.exec(content)) !== null) {
    findings('12_Webhooks', [`${match[1]} in ${name}`]);
  }

  const webhookConfigRe = /["'`]webhookUrl["'`]|["'`]webhook_url["'`]|["'`]callbackUrl["'`]|["'`]callback_url["'`]/gi;
  while ((match = webhookConfigRe.exec(content)) !== null) {
    findings('12_Webhook_Config', [`${match[0]} found in ${name}`]);
  }

  // ── Feature 13: Environment Variable Reference ──
  const envRe = /(?:process\.env|import\.meta\.env|Deno\.env)\.([A-Za-z0-9_]+)/g;
  while ((match = envRe.exec(content)) !== null) {
    findings('13_Env_Vars', [`${match[0]} in ${name}`]);
  }

  const envConfigRe = /["'`](NODE_ENV|API_KEY|API_URL|BASE_URL|DB_HOST|DB_PASSWORD|SECRET|SECRET_KEY|JWT_SECRET|SESSION_SECRET|SALT|ENCRYPTION_KEY|AUTH_TOKEN|STRIPE|SENDGRID|TWILIO|AWS_|GCP_|AZURE_|DATABASE_URL|REDIS_URL|MONGO_|POSTGRES_)["'`]/gi;
  while ((match = envConfigRe.exec(content)) !== null) {
    findings('13_Env_Config_Keys', [`${match[0]} in ${name}`]);
  }

  // ── Feature 14: CORS Misconfig Checker ──
  const corsRe = /["'`](Access-Control-Allow-Origin|Access-Control-Allow-Credentials|cors|CORS)["'`]\s*[:=]\s*["'`]([^"'`]+)["'`]/gi;
  while ((match = corsRe.exec(content)) !== null) {
    findings('14_CORS_Config', [`${match[1]}: ${match[2].substring(0, 80)} in ${name}`]);
  }

  // ── Feature 15: Version Fingerprinting ──
  const versionPatterns = [
    { lib: 'React', re: /react@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Angular', re: /@angular\/core@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Vue', re: /vue@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Next.js', re: /next@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Nuxt', re: /nuxt@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'jQuery', re: /jquery@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Bootstrap', re: /bootstrap@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Lodash', re: /lodash@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Axios', re: /axios@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
    { lib: 'Express', re: /express@?([0-9]+\.[0-9]+\.[0-9]+)/gi },
  ];
  for (const vp of versionPatterns) {
    while ((match = vp.re.exec(content)) !== null) {
      findings('15_Versions', [`${vp.lib} ${match[1]} in ${name}`]);
    }
  }

  // ── Feature 16: Path Traversal Pattern Scanner ──
  const traversalRe = /["']\.\.\/|\.\.[\\\/]|__dirname\s*\+\s*["']\/|path\.join\([^)]*\.\.|path\.resolve\([^)]*\.\./gi;
  while ((match = traversalRe.exec(content)) !== null) {
    findings('16_Path_Traversal', [`${match[0].substring(0, 60)} in ${name}`]);
  }

  const userPathRe = /["'`](filename|filePath|filepath|path|file_name|uploadPath)["'`]\s*[:=]\s*["'`]([^"'`]*)["'`]/gi;
  while ((match = userPathRe.exec(content)) !== null) {
    findings('16_User_Controlled_Paths', [`${match[1]}: ${match[2].substring(0, 60)} in ${name}`]);
  }

  // ── Feature 17: DOM XSS Sink Detection ──
  const xssSinks = [
    { sink: 'innerHTML', re: /\.innerHTML\s*=/g },
    { sink: 'outerHTML', re: /\.outerHTML\s*=/g },
    { sink: 'document.write', re: /document\.write\s*\(/g },
    { sink: 'eval()', re: /eval\s*\(/g },
    { sink: 'setTimeout(string)', re: /setTimeout\s*\(\s*["'`]/g },
    { sink: 'setInterval(string)', re: /setInterval\s*\(\s*["'`]/g },
    { sink: 'new Function()', re: /new\s+Function\s*\(/g },
    { sink: 'insertAdjacentHTML', re: /\.insertAdjacentHTML\s*\(/g },
    { sink: 'location.href', re: /location\s*\.\s*href\s*=/g },
    { sink: 'location.hash', re: /location\s*\.\s*hash\s*=/g },
    { sink: 'srcdoc', re: /\.srcdoc\s*=/g },
    { sink: 'script.textContent', re: /\.textContent\s*=/g },
  ];
  for (const xs of xssSinks) {
    while ((match = xs.re.exec(content)) !== null) {
      findings('17_XSS_Sinks', [`${xs.sink} in ${name}`]);
    }
  }

  // ── Feature 18: WebSocket Endpoint Finder ──
  const wsRe = /["'`](wss?:\/\/[^"'`]+)["'`]/gi;
  while ((match = wsRe.exec(content)) !== null) {
    findings('18_WebSockets', [`${match[1]} in ${name}`]);
  }

  const wsConfigRe = /["'`](wsUrl|ws_url|websocketUrl|websocket_url|socketUrl|socket_url|wssUrl|wss_url)["'`]/gi;
  while ((match = wsConfigRe.exec(content)) !== null) {
    findings('18_WebSocket_Config', [`${match[0]} in ${name}`]);
  }

  // ── Feature 19: Suspicious Comment Extraction ──
  const commentPatterns = [
    { type: 'TODO', re: /\/\/\s*(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND|HARCODED|TEMPORARY|REMOVE|SECURITY)\s*[:-]?\s*(.*)$/gim },
    { type: 'Block TODO', re: /\*?\s*(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND|TEMPORARY|REMOVE|SECURITY)\s*[:-]?\s*([^*]*)\s*\*/gi },
  ];
  for (const cp of commentPatterns) {
    while ((match = cp.re.exec(content)) !== null) {
      const comment = (match[1] || match[0]).trim();
      if (comment.length > 3) {
        findings('19_Suspicious_Comments', [`${cp.type}: ${comment.substring(0, 100)} in ${name}`]);
      }
    }
  }

  // ── Feature 20: Batch Comparison Markers ──
  const buildRe = /["'`](buildId|build_id|buildNumber|build_number|version|deployId|deploy_id|release|gitCommit|git_commit|commitHash|commit_hash)["'`]\s*[:=]\s*["'`]([^"'`]{6,50})["'`]/gi;
  while ((match = buildRe.exec(content)) !== null) {
    findings('20_Build_Markers', [`${match[1]}: ${match[2]} in ${name}`]);
  }

});

// ── Output ──
const featureOrder = [
  '1_JWT_Tokens', '2_Cloud_Services', '3_GraphQL_Operations', '3_GraphQL_Endpoints',
  '4_Source_Maps', '5_Route_Tree', '6_High_Entropy', '7_OAuth_Config',
  '8_Internal_IPs', '9_Email_Templates', '9_SSTI_Probes', '10_Feature_Flags',
  '11_Third_Party_Services', '12_Webhooks', '12_Webhook_Config', '13_Env_Vars',
  '13_Env_Config_Keys', '14_CORS_Config', '15_Versions', '16_Path_Traversal',
  '16_User_Controlled_Paths', '17_XSS_Sinks', '18_WebSockets', '18_WebSocket_Config',
  '19_Suspicious_Comments', '20_Build_Markers',
];

const titles = {
  '1_JWT_Tokens': 'Feature 1: JWT Token Decoder',
  '2_Cloud_Services': 'Feature 2: Cloud Service Enumeration (S3/Firebase/GCP/Azure/CloudFront/Lambda)',
  '3_GraphQL_Operations': 'Feature 3a: GraphQL Operations (Queries/Mutations/Subscriptions/Fragments)',
  '3_GraphQL_Endpoints': 'Feature 3b: GraphQL Endpoints',
  '4_Source_Maps': 'Feature 4: Source Map Discovery',
  '5_Route_Tree': 'Feature 5: API Route Tree',
  '6_High_Entropy': 'Feature 6: High-Entropy String Scanner (potential custom keys)',
  '7_OAuth_Config': 'Feature 7: OAuth Flow Analysis',
  '8_Internal_IPs': 'Feature 8: Hardcoded IP & Port Finder',
  '9_Email_Templates': 'Feature 9a: Email Templates (potential SSTI)',
  '9_SSTI_Probes': 'Feature 9b: SSTI Probe Detection (Jinja2/ERB/Handlebars)',
  '10_Feature_Flags': 'Feature 10: Feature Flag Reporter',
  '11_Third_Party_Services': 'Feature 11: Third-Party Service Mapper (20+ services)',
  '12_Webhooks': 'Feature 12a: Webhook URL Collector',
  '12_Webhook_Config': 'Feature 12b: Webhook Configuration Keys',
  '13_Env_Vars': 'Feature 13a: Environment Variable References',
  '13_Env_Config_Keys': 'Feature 13b: Sensitive Config Key Names',
  '14_CORS_Config': 'Feature 14: CORS Misconfiguration Checker',
  '15_Versions': 'Feature 15: Library Version Fingerprinting',
  '16_Path_Traversal': 'Feature 16a: Path Traversal Pattern Scanner',
  '16_User_Controlled_Paths': 'Feature 16b: User-Controlled File Paths',
  '17_XSS_Sinks': 'Feature 17: DOM XSS Sink Detection',
  '18_WebSockets': 'Feature 18a: WebSocket Endpoint URLs',
  '18_WebSocket_Config': 'Feature 18b: WebSocket Configuration Keys',
  '19_Suspicious_Comments': 'Feature 19: Suspicious Comment Extractor (TODO/FIXME/HACK/SECURITY)',
  '20_Build_Markers': 'Feature 20: Build/Version Comparison Markers',
};

console.log(`\n${'#'.repeat(70)}`);
console.log(`  JS DEEP ANALYZER -- 20 Features on ${files.length} file(s)`);
console.log(`${'#'.repeat(70)}`);

let totalFindings = 0;
for (const key of featureOrder) {
  const items = allFindings[key];
  if (items && items.length > 0) {
    const uniqueItems = unique(items);
    printSection(titles[key] || key, uniqueItems);
    totalFindings += uniqueItems.length;
  }
}

console.log(`\n${'#'.repeat(70)}`);
console.log(`  Total: ${totalFindings} findings across ${files.length} file(s)`);
console.log(`${'#'.repeat(70)}\n`);

if (jsonOutput && outputJsonPath) {
  const jsonData = {};
  for (const key of featureOrder) {
    if (allFindings[key]) jsonData[key] = unique(allFindings[key]);
  }
  jsonData._meta = { files: files.length, totalFindings, input: inputPath };
  fs.writeFileSync(outputJsonPath, JSON.stringify(jsonData, null, 2));
  console.log(`JSON output written to: ${outputJsonPath}`);
}
