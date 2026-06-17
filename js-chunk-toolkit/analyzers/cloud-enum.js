const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
if (args.length === 0) { console.log('Usage: node cloud-enum.js <file_or_dir>'); process.exit(1); }

function load(p) {
  if (fs.statSync(p).isDirectory()) {
    return fs.readdirSync(p).filter(f => /\.(js|mjs|cjs|map|json)$/.test(f))
      .flatMap(f => ({ name: f, content: fs.readFileSync(path.join(p, f), 'utf-8') }));
  }
  return [{ name: path.basename(p), content: fs.readFileSync(p, 'utf-8') }];
}

const files = load(args[0]);
const allContent = files.map(f => f.content).join('\n');

const services = {};

function add(category, provider, value, file) {
  if (!services[category]) services[category] = {};
  if (!services[category][provider]) services[category][provider] = [];
  services[category][provider].push({ value, file });
}

const patterns = [
  // AWS
  { category: 'Storage', provider: 'S3 Bucket', re: /["']([a-z0-9.-]+\.s3\.amazonaws\.com)["']/gi },
  { category: 'Storage', provider: 'S3 Bucket', re: /["']([a-z0-9.-]+\.s3-website[^"']+)["']/gi },
  { category: 'Storage', provider: 'S3 Bucket', re: /s3:\/\/([a-z0-9.-]+)/gi },
  { category: 'Storage', provider: 'S3 Bucket', re: /["'](https?:\/\/[a-z0-9.-]+\.s3\.[^"']+)["']/gi },
  { category: 'CDN', provider: 'CloudFront', re: /[a-z0-9]+\.cloudfront\.net/gi },
  { category: 'Compute', provider: 'Lambda URL', re: /[a-z0-9-]+\.lambda-url\.[a-z0-9-]+\.on\.aws/gi },
  { category: 'Compute', provider: 'API Gateway', re: /[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com/gi },
  { category: 'DNS', provider: 'Elastic Beanstalk', re: /[a-z0-9-]+\.elasticbeanstalk\.com/gi },
  { category: 'DNS', provider: 'RDS', re: /[a-z0-9-]+\.rds\.amazonaws\.com/gi },
  { category: 'DNS', provider: 'ELB', re: /[a-z0-9-]+\.elb\.amazonaws\.com/gi },

  // GCP
  { category: 'Database', provider: 'Firebase Realtime', re: /[a-z0-9-]+\.firebaseio\.com/gi },
  { category: 'Database', provider: 'Firebase DB', re: /[a-z0-9-]+\.firebasedatabase\.app/gi },
  { category: 'Hosting', provider: 'Firebase App', re: /[a-z0-9-]+\.firebaseapp\.com/gi },
  { category: 'Hosting', provider: 'Firebase Web', re: /[a-z0-9-]+\.web\.app/gi },
  { category: 'Compute', provider: 'Cloud Functions', re: /[a-z0-9-]+\.cloudfunctions\.net/gi },
  { category: 'Hosting', provider: 'App Engine', re: /[a-z0-9-]+\.appspot\.com/gi },
  { category: 'Storage', provider: 'GCS', re: /storage\.googleapis\.com\/[a-z0-9-]+/gi },
  { category: 'Compute', provider: 'Cloud Run', re: /[a-z0-9-]+-uc\.a\.run\.app/gi },

  // Azure
  { category: 'Storage', provider: 'Blob Storage', re: /[a-z0-9]+\.blob\.core\.windows\.net/gi },
  { category: 'App Service', provider: 'App Service', re: /[a-z0-9-]+\.azurewebsites\.net/gi },
  { category: 'CDN', provider: 'Azure CDN', re: /[a-z0-9-]+\.azureedge\.net/gi },
  { category: 'CDN', provider: 'Azure Front Door', re: /[a-z0-9-]+\.azurefd\.net/gi },
  { category: 'Database', provider: 'Cosmos DB', re: /[a-z0-9-]+\.documents\.azure\.com/gi },
  { category: 'Database', provider: 'SQL Server', re: /[a-z0-9-]+\.database\.windows\.net/gi },

  // Cloudflare
  { category: 'CDN', provider: 'Cloudflare', re: /[a-z0-9-]+\.cloudflare\.com/gi },
  { category: 'Workers', provider: 'Cloudflare Workers', re: /[a-z0-9-]+\.workers\.dev/gi },
  { category: 'Pages', provider: 'Cloudflare Pages', re: /[a-z0-9-]+\.pages\.dev/gi },

  // Other
  { category: 'CDN', provider: 'Fastly', re: /[a-z0-9-]+\.fastly\.net/gi },
  { category: 'CDN', provider: 'StackPath', re: /[a-z0-9-]+\.stackpathcdn\.com/gi },
  { category: 'CDN', provider: 'KeyCDN', re: /[a-z0-9-]+\.kxcdn\.com/gi },
  { category: 'CDN', provider: 'UNPKG', re: /unpkg\.com/gi },
  { category: 'CDN', provider: 'jsDelivr', re: /cdn\.jsdelivr\.net/gi },
  { category: 'CDN', provider: 'cdnjs', re: /cdnjs\.cloudflare\.com/gi },
];

files.forEach(({ name, content }) => {
  for (const p of patterns) {
    let match;
    while ((match = p.re.exec(content)) !== null) {
      add(p.category, p.provider, match[0], name);
    }
  }
});

console.log(`\n${'='.repeat(70)}`);
console.log(`  Cloud Service Enumeration -- ${files.length} file(s)`);
console.log(`${'='.repeat(70)}`);

let total = 0;
for (const [category, providers] of Object.entries(services)) {
  console.log(`\n  ${category}:`);
  for (const [provider, items] of Object.entries(providers)) {
    const unique = [...new Set(items.map(i => i.value))];
    console.log(`    ${provider}: ${unique.length} unique`);
    unique.slice(0, 8).forEach(u => console.log(`      ${u.substring(0, 100)}`));
    if (unique.length > 8) console.log(`      ... and ${unique.length - 8} more`);
    total += unique.length;
  }
}

console.log(`\n  Total cloud assets discovered: ${total}`);
console.log(`${'='.repeat(70)}\n`);
