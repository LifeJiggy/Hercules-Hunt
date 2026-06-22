const http = require('http');
const https = require('https');

function sendWebhook(webhookUrl, payload, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const url = new URL(webhookUrl);
      const client = url.protocol === 'https:' ? https : http;
      const body = JSON.stringify(payload);
      const req = client.request(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'JS-Chunk-Toolkit-Webhook/1.0'
        },
        timeout: options.timeout || 10000
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data.substring(0, 500) }));
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
      req.write(body);
      req.end();
    } catch (e) { reject(e); }
  });
}

function slackFormatter(findings) {
  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high = findings.filter(f => f.severity === 'HIGH');
  const blocks = [];
  blocks.push({ type: 'header', text: { type: 'plain_text', text: '🔍 JS Chunk Analysis Complete' } });
  blocks.push({ type: 'section', text: { type: 'mrkdwn', text: `*CRITICAL:* ${critical.length}  *HIGH:* ${high.length}` } });
  for (const f of [...critical, ...high].slice(0, 10)) {
    blocks.push({
      type: 'section',
      text: { type: 'mrkdwn', text: `*[${f.severity}]* ${f.type || f.pattern || 'Finding'}\n\`${(f.value || f.name || '').substring(0, 80)}\`` }
    });
  }
  return { blocks };
}

if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length < 2) {
    console.log('Usage: node webhook-alerter.js <webhook_url> <findings.json> [--severity CRITICAL]');
    process.exit(1);
  }

  const webhookUrl = args[0];
  const findings = JSON.parse(fs.readFileSync(args[1], 'utf-8'));
  const input = Array.isArray(findings) ? findings : findings.findings || findings.secrets || [];
  const severityFlag = args.indexOf('--severity');
  const minSeverity = severityFlag > -1 ? args[severityFlag + 1] : 'HIGH';
  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

  const filtered = input.filter(f => (sevOrder[f.severity] || 99) <= (sevOrder[minSeverity] || 1));
  if (filtered.length === 0) { console.log('No findings meeting severity threshold.'); process.exit(0); }

  const payload = slackFormatter(filtered);
  sendWebhook(webhookUrl, payload)
    .then(res => console.log(`[OK] Webhook sent: ${res.status}`))
    .catch(e => console.error(`Error: ${e.message}`));
}

module.exports = { sendWebhook, slackFormatter };
